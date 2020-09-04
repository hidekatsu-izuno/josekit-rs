use anyhow::bail;
use once_cell::sync::Lazy;
use openssl::bn::BigNumRef;
use openssl::hash::MessageDigest;
use regex::bytes::{NoExpand, Regex};
use std::time::SystemTime;
use std::fmt::Display;

use std::ptr;
use std::os::raw::c_int;
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Private};
use openssl_sys::{
    EVP_PKEY_CTX_new_id,
    EVP_PKEY_keygen_init,
    EVP_PKEY_CTX_free,
    EVP_PKEY_keygen,
    EVP_PKEY_free,
    i2d_PrivateKey
};

use crate::jwk::Jwk;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SourceValue {
    Jwk(Jwk),
    Bytes(Vec<u8>),
    BytesArray(Vec<Vec<u8>>),
    StringArray(Vec<String>),
    SystemTime(SystemTime),
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub fn name(&self) -> &str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }
    
    pub fn signature_len(&self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    pub fn message_digest(&self) -> MessageDigest {
        match self {
            Self::Sha256 => MessageDigest::sha256(),
            Self::Sha384 => MessageDigest::sha384(),
            Self::Sha512 => MessageDigest::sha512(),
        }
    }
}

impl Display for HashAlgorithm {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

pub fn ceiling(len: usize, div: usize) -> usize {
    (len + (div - 1)) / div
}

pub fn parse_pem(input: &[u8]) -> anyhow::Result<(String, Vec<u8>)> {
    static RE_PEM: Lazy<Regex> = Lazy::new(|| {
        Regex::new(concat!(
            r"^",
            r"-----BEGIN ([A-Z0-9 -]+)-----[\t ]*(?:\r\n|[\r\n])",
            r"([\t\r\n a-zA-Z0-9+/=]+)",
            r"-----END ([A-Z0-9 -]+)-----[\t ]*(?:\r\n|[\r\n])?",
            r"$"
        ))
        .unwrap()
    });

    static RE_FILTER: Lazy<Regex> = Lazy::new(|| Regex::new("[\t\r\n ]").unwrap());

    let result = if let Some(caps) = RE_PEM.captures(input) {
        match (caps.get(1), caps.get(2), caps.get(3)) {
            (Some(ref m1), Some(ref m2), Some(ref m3)) if m1.as_bytes() == m3.as_bytes() => {
                let alg = String::from_utf8(m1.as_bytes().to_vec())?;
                let base64_data = RE_FILTER.replace_all(m2.as_bytes(), NoExpand(b""));
                let data = base64::decode_config(&base64_data, base64::STANDARD)?;
                (alg, data)
            }
            _ => bail!("Mismatched the begging and ending label."),
        }
    } else {
        bail!("Invalid PEM format.");
    };

    Ok(result)
}

pub fn num_to_vec(num: &BigNumRef, len: usize) -> Vec<u8> {
    let vec = num.to_vec();
    if vec.len() < len {
        let mut tmp = Vec::with_capacity(len);
        for _ in 0..(len - vec.len()) {
            tmp.push(0);
        }
        tmp.extend_from_slice(&vec);
        tmp
    } else {
        vec
    }
}

const NID_X25519: c_int = 1034;
const NID_X448: c_int = 1035;

pub fn generate_x25519() -> Result<PKey<Private>, ErrorStack> {
    generate_der(NID_X25519)
}

pub fn generate_x448() -> Result<PKey<Private>, ErrorStack> {
    generate_der(NID_X448)
}

fn generate_der(nid: c_int) -> Result<PKey<Private>, ErrorStack> {
    let der = unsafe {
        let pctx = match EVP_PKEY_CTX_new_id(nid, ptr::null_mut()) {
            val if val.is_null() => return Err(ErrorStack::get()),
            val => val,
        };

        if EVP_PKEY_keygen_init(pctx) <= 0 {
            EVP_PKEY_CTX_free(pctx);
            return Err(ErrorStack::get());
        }

        let mut pkey = ptr::null_mut();
        if EVP_PKEY_keygen(pctx, &mut pkey) <= 0 {
            EVP_PKEY_CTX_free(pctx);
            return Err(ErrorStack::get());
        }

        let len = match i2d_PrivateKey(pkey, ptr::null_mut()) {
            val if val <= 0 => {
                EVP_PKEY_free(pkey);
                return Err(ErrorStack::get());
            },
            val => val,
        };

        let mut der = vec![0; len as usize];
        if i2d_PrivateKey(pkey, &mut der.as_mut_ptr()) != len {
            EVP_PKEY_free(pkey);
            return Err(ErrorStack::get());
        }

        der
    };

    PKey::private_key_from_der(&der)
}
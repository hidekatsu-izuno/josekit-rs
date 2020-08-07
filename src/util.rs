use anyhow::bail;
use once_cell::sync::Lazy;
use regex::bytes::{NoExpand, Regex};
use std::time::SystemTime;
use openssl::bn::BigNumRef;

use crate::jwk::Jwk;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SourceValue {
    Jwk(Jwk),
    Bytes(Vec<u8>),
    BytesArray(Vec<Vec<u8>>),
    StringArray(Vec<String>),
    SystemTime(SystemTime),
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


use std::sync::{Arc, OnceLock};

use anyhow::{bail, Context};
use aws_lc_rs::{
    encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der},
    rand::SystemRandom,
    rsa as lc,
    signature::{self, KeyPair},
};
use pkcs8::{der::Decode, PrivateKeyInfoRef, SubjectPublicKeyInfoRef};
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPublicKey, RsaPublicKeyRef};

use super::rsa_rustcrypto as rustcrypto;
use crate::util::{oid::ObjectIdentifier, HashAlgorithm};

#[derive(Debug, Clone)]
pub(crate) enum Private {
    Aws(Arc<AwsPrivate>),
    Rust(Box<rsa::PrivateKey>),
}

#[derive(Debug)]
pub(crate) struct AwsPrivate {
    key: lc::KeyPair,
    rsa1_5: OnceLock<anyhow::Result<rsa::PrivateKey>>,
}

impl AwsPrivate {
    fn new(key: lc::KeyPair) -> Self {
        Self {
            key,
            rsa1_5: OnceLock::new(),
        }
    }

    fn pkcs8(&self) -> anyhow::Result<Pkcs8V1Der<'static>> {
        Ok(self.key.as_der()?)
    }

    fn rsa1_5(&self) -> anyhow::Result<&rsa::PrivateKey> {
        self.rsa1_5
            .get_or_init(|| Ok(rsa::PrivateKey::from_pkcs1_der(&aws_private_der(self)?)?))
            .as_ref()
            .map_err(|err| anyhow::anyhow!("Unable to load the RSA1_5 key: {err}"))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Public {
    key: lc::PublicKey,
    size: usize,
}

impl Public {
    fn new(key: lc::PublicKey) -> anyhow::Result<Self> {
        let size = RsaPublicKeyRef::from_der(key.as_ref())?
            .modulus
            .as_bytes()
            .len();
        Ok(Self { key, size })
    }

    fn encrypting_key(&self) -> anyhow::Result<lc::PublicEncryptingKey> {
        let der: PublicKeyX509Der<'_> = self.key.as_der()?;
        Ok(lc::PublicEncryptingKey::from_der(der.as_ref())?)
    }
}

pub(super) fn generate(bits: usize) -> anyhow::Result<Private> {
    let size = match bits {
        2048 => lc::KeySize::Rsa2048,
        3072 => lc::KeySize::Rsa3072,
        4096 => lc::KeySize::Rsa4096,
        8192 => lc::KeySize::Rsa8192,
        _ => {
            let key = rustcrypto::generate(bits)?;
            if bits < 2048 {
                return Ok(Private::Rust(Box::new(key)));
            }
            use rsa::pkcs1::EncodeRsaPrivateKey;
            let der = key.to_pkcs1_der()?;
            return Ok(Private::Aws(Arc::new(AwsPrivate::new(
                lc::KeyPair::from_der(der.as_bytes())?,
            ))));
        }
    };
    Ok(Private::Aws(Arc::new(AwsPrivate::new(
        lc::KeyPair::generate(size)?,
    ))))
}

fn check_oid(actual: pkcs8::ObjectIdentifier, expected: &ObjectIdentifier) -> anyhow::Result<()> {
    if !actual
        .arcs()
        .map(u64::from)
        .eq(expected.into_iter().copied())
    {
        bail!("Invalid RSA algorithm identifier.");
    }
    Ok(())
}

pub(super) fn private_key_from_der(der: &[u8], oid: &ObjectIdentifier) -> anyhow::Result<Private> {
    let info = PrivateKeyInfoRef::from_der(der)?;
    check_oid(info.algorithm.oid, oid)?;
    let raw = info.private_key.as_bytes();
    match lc::KeyPair::from_der(raw) {
        Ok(key) => Ok(Private::Aws(Arc::new(AwsPrivate::new(key)))),
        Err(err) => {
            use rsa::traits::PublicKeyParts;
            let key = rsa::PrivateKey::from_pkcs1_der(raw)?;
            if key.n().bit_width() >= 2048 {
                return Err(err.into());
            }
            Ok(Private::Rust(Box::new(key)))
        }
    }
}

pub(super) fn public_key_from_der(der: &[u8], oid: &ObjectIdentifier) -> anyhow::Result<Public> {
    let info = SubjectPublicKeyInfoRef::from_der(der)?;
    check_oid(info.algorithm.oid, oid)?;
    let raw = info
        .subject_public_key
        .as_bytes()
        .context("Invalid RSA public key bit string.")?;
    Public::new(lc::PublicKey::from_der(raw)?)
}

pub(super) fn size(key: &Private) -> usize {
    match key {
        Private::Aws(key) => key.key.public_modulus_len(),
        Private::Rust(key) => rustcrypto::size(key),
    }
}

pub(super) fn public_size(key: &Public) -> usize {
    key.size
}

pub(super) fn to_public(key: &Private) -> anyhow::Result<Public> {
    match key {
        Private::Aws(key) => Public::new(key.key.public_key().clone()),
        Private::Rust(key) => {
            let der = key.to_public_key().to_pkcs1_der()?;
            Public::new(lc::PublicKey::from_der(der.as_bytes())?)
        }
    }
}

fn aws_private_der(key: &AwsPrivate) -> anyhow::Result<pkcs8::der::zeroize::Zeroizing<Vec<u8>>> {
    let pkcs8 = key.pkcs8()?;
    let info = PrivateKeyInfoRef::from_der(pkcs8.as_ref())?;
    Ok(pkcs8::der::zeroize::Zeroizing::new(
        info.private_key.as_bytes().to_vec(),
    ))
}

pub(super) fn export_private(key: &Private) -> anyhow::Result<Vec<u8>> {
    match key {
        Private::Aws(key) => Ok(aws_private_der(key)?.to_vec()),
        Private::Rust(key) => rustcrypto::export_private(key),
    }
}

pub(super) fn export_public(key: &Public) -> anyhow::Result<Vec<u8>> {
    Ok(key.key.as_ref().to_vec())
}

fn oaep_algorithm(hash: HashAlgorithm) -> &'static lc::OaepAlgorithm {
    match hash {
        HashAlgorithm::Sha1 => &lc::OAEP_SHA1_MGF1SHA1,
        HashAlgorithm::Sha256 => &lc::OAEP_SHA256_MGF1SHA256,
        HashAlgorithm::Sha384 => &lc::OAEP_SHA384_MGF1SHA384,
        HashAlgorithm::Sha512 => &lc::OAEP_SHA512_MGF1SHA512,
    }
}

pub(super) fn encrypt(
    key: &Public,
    hash: Option<HashAlgorithm>,
    message: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let key = key.encrypting_key()?;
    let mut ciphertext = vec![0; key.key_size_bytes()];
    let len = match hash {
        Some(hash) => lc::OaepPublicEncryptingKey::new(key)?
            .encrypt(oaep_algorithm(hash), message, &mut ciphertext, None)?
            .len(),
        None => lc::Pkcs1PublicEncryptingKey::new(key)?
            .encrypt(message, &mut ciphertext)?
            .len(),
    };
    ciphertext.truncate(len);
    Ok(ciphertext)
}

pub(super) fn decrypt(
    key: &Private,
    hash: Option<HashAlgorithm>,
    ciphertext: &[u8],
    key_len: usize,
) -> anyhow::Result<Vec<u8>> {
    let Some(hash) = hash else {
        // AWS-LC reports PKCS#1 v1.5 padding failures explicitly.
        let key = match key {
            Private::Aws(key) => key.rsa1_5()?,
            Private::Rust(key) => key,
        };
        return rustcrypto::decrypt_rsa1_5(key, ciphertext, key_len);
    };
    let Private::Aws(key) = key else {
        bail!("RSA-OAEP requires a key of at least 2048 bits.");
    };
    let pkcs8 = key.pkcs8()?;
    let key =
        lc::OaepPrivateDecryptingKey::new(lc::PrivateDecryptingKey::from_pkcs8(pkcs8.as_ref())?)?;
    let mut plaintext = vec![0; key.min_output_size()];
    let len = key
        .decrypt(oaep_algorithm(hash), ciphertext, &mut plaintext, None)?
        .len();
    plaintext.truncate(len);
    Ok(plaintext)
}

pub(super) fn sign(
    key: &Private,
    hash: HashAlgorithm,
    pss: bool,
    message: &[u8],
) -> anyhow::Result<Vec<u8>> {
    use signature::*;
    let Private::Aws(key) = key else {
        bail!("RSA signatures require a key of at least 2048 bits.");
    };
    let key = &key.key;
    let algorithm = match (pss, hash) {
        (false, HashAlgorithm::Sha256) => &RSA_PKCS1_SHA256,
        (false, HashAlgorithm::Sha384) => &RSA_PKCS1_SHA384,
        (false, HashAlgorithm::Sha512) => &RSA_PKCS1_SHA512,
        (true, HashAlgorithm::Sha256) => &RSA_PSS_SHA256,
        (true, HashAlgorithm::Sha384) => &RSA_PSS_SHA384,
        (true, HashAlgorithm::Sha512) => &RSA_PSS_SHA512,
        (_, HashAlgorithm::Sha1) => bail!("SHA-1 is unsupported for JOSE signatures."),
    };
    let mut signature = vec![0; key.public_modulus_len()];
    key.sign(algorithm, &SystemRandom::new(), message, &mut signature)?;
    Ok(signature)
}

pub(super) fn verify(
    key: &Public,
    hash: HashAlgorithm,
    pss: bool,
    message: &[u8],
    signature: &[u8],
) -> anyhow::Result<()> {
    use signature::*;
    let algorithm = match (pss, hash) {
        (false, HashAlgorithm::Sha256) => &RSA_PKCS1_2048_8192_SHA256,
        (false, HashAlgorithm::Sha384) => &RSA_PKCS1_2048_8192_SHA384,
        (false, HashAlgorithm::Sha512) => &RSA_PKCS1_2048_8192_SHA512,
        (true, HashAlgorithm::Sha256) => &RSA_PSS_2048_8192_SHA256,
        (true, HashAlgorithm::Sha384) => &RSA_PSS_2048_8192_SHA384,
        (true, HashAlgorithm::Sha512) => &RSA_PSS_2048_8192_SHA512,
        (_, HashAlgorithm::Sha1) => bail!("SHA-1 is unsupported for JOSE signatures."),
    };
    Ok(UnparsedPublicKey::new(algorithm, key.key.as_ref()).verify(message, signature)?)
}

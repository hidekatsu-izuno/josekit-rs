use anyhow::{bail, Context};
use rand::rngs::SysRng;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::{der::Decode, PrivateKeyInfoRef, SubjectPublicKeyInfoRef};

use crate::util::{oid::ObjectIdentifier, HashAlgorithm};

pub(super) fn private_key_from_der(
    der: &[u8],
    oid: &ObjectIdentifier,
) -> anyhow::Result<rsa::PrivateKey> {
    let info = PrivateKeyInfoRef::from_der(der)?;
    if !info
        .algorithm
        .oid
        .arcs()
        .map(u64::from)
        .eq(oid.into_iter().copied())
    {
        bail!("Invalid RSA private key algorithm identifier.");
    }
    Ok(rsa::PrivateKey::from_pkcs1_der(
        info.private_key.as_bytes(),
    )?)
}

pub(super) fn public_key_from_der(
    der: &[u8],
    oid: &ObjectIdentifier,
) -> anyhow::Result<rsa::PublicKey> {
    let info = SubjectPublicKeyInfoRef::from_der(der)?;
    if !info
        .algorithm
        .oid
        .arcs()
        .map(u64::from)
        .eq(oid.into_iter().copied())
    {
        bail!("Invalid RSA public key algorithm identifier.");
    }
    let key = info
        .subject_public_key
        .as_bytes()
        .context("Invalid RSA public key bit string.")?;
    Ok(rsa::PublicKey::from_pkcs1_der(key)?)
}

macro_rules! with_digest {
    ($hash:expr, |$digest:ident| $op:expr) => {
        match $hash {
            HashAlgorithm::Sha1 => {
                type $digest = sha1::Sha1;
                $op
            }
            HashAlgorithm::Sha256 => {
                type $digest = sha2::Sha256;
                $op
            }
            HashAlgorithm::Sha384 => {
                type $digest = sha2::Sha384;
                $op
            }
            HashAlgorithm::Sha512 => {
                type $digest = sha2::Sha512;
                $op
            }
        }
    };
}

pub(super) fn encrypt(
    key: &rsa::PublicKey,
    hash: Option<HashAlgorithm>,
    message: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut rng = SysRng;
    Ok(match hash {
        Some(hash) => with_digest!(hash, |Digest| key
            .oaep_encrypt_with_rng::<Digest, _>(&mut rng, message))?,
        None => key.pkcs1v15_encrypt_with_rng(&mut rng, message)?,
    })
}

pub(super) fn decrypt(
    key: &rsa::PrivateKey,
    hash: Option<HashAlgorithm>,
    ciphertext: &[u8],
    key_len: usize,
) -> anyhow::Result<Vec<u8>> {
    let mut rng = SysRng;
    match hash {
        Some(hash) => Ok(with_digest!(hash, |Digest| {
            key.oaep_decrypt_with_rng::<Digest, _>(&mut rng, ciphertext)
        })?),
        None => {
            // RFC 7516 §11.5 requires substituting a random CEK on RSA1_5 rejection.
            let mut fallback = vec![0; key_len];
            crate::util::fill_random_bytes!(&mut fallback)?;
            match key.pkcs1v15_decrypt_with_rng(&mut rng, ciphertext) {
                Ok(message) if message.len() == key_len => Ok(message),
                _ => Ok(fallback),
            }
        }
    }
}

pub(super) fn sign(
    key: &rsa::PrivateKey,
    hash: HashAlgorithm,
    pss: bool,
    message: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let mut rng = SysRng;
    Ok(with_digest!(hash, |Digest| {
        if pss {
            key.pss_sign_with_rng::<Digest, _>(&mut rng, message)
        } else {
            key.pkcs1v15_sign_with_rng::<Digest, _>(&mut rng, message)
        }
    })?)
}

pub(super) fn verify(
    key: &rsa::PublicKey,
    hash: HashAlgorithm,
    pss: bool,
    message: &[u8],
    signature: &[u8],
) -> anyhow::Result<()> {
    Ok(with_digest!(hash, |Digest| {
        if pss {
            key.pss_verify::<Digest>(message, signature)
        } else {
            key.pkcs1v15_verify::<Digest>(message, signature)
        }
    })?)
}

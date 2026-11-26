use anyhow::bail;
#[cfg(not(feature = "aws-lc-rs"))]
use anyhow::Context;
use getrandom::SysRng;
#[cfg(not(feature = "aws-lc-rs"))]
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
#[cfg(not(feature = "aws-lc-rs"))]
use rsa::pkcs8::{der::Decode, PrivateKeyInfoRef, SubjectPublicKeyInfoRef};

#[cfg(not(feature = "aws-lc-rs"))]
use crate::util::oid::ObjectIdentifier;
#[cfg(not(feature = "aws-lc-rs"))]
use crate::util::HashAlgorithm;

#[cfg(not(feature = "aws-lc-rs"))]
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

#[cfg(not(feature = "aws-lc-rs"))]
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

#[cfg(not(feature = "aws-lc-rs"))]
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

#[cfg(not(feature = "aws-lc-rs"))]
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

#[cfg(not(feature = "aws-lc-rs"))]
pub(super) fn decrypt(
    key: &rsa::PrivateKey,
    hash: Option<HashAlgorithm>,
    ciphertext: &[u8],
    key_len: usize,
) -> anyhow::Result<Vec<u8>> {
    match hash {
        Some(hash) => Ok(with_digest!(hash, |Digest| {
            key.oaep_decrypt_with_rng::<Digest, _>(&mut SysRng, ciphertext)
        })?),
        None => decrypt_rsa1_5(key, ciphertext, key_len),
    }
}

pub(super) fn decrypt_rsa1_5(
    key: &rsa::PrivateKey,
    ciphertext: &[u8],
    key_len: usize,
) -> anyhow::Result<Vec<u8>> {
    // RFC 7516 §11.5 requires substituting a random CEK on RSA1_5 rejection.
    let mut fallback = vec![0; key_len];
    crate::util::fill_random_bytes!(&mut fallback)?;
    match key.pkcs1v15_decrypt_with_rng(&mut SysRng, ciphertext) {
        Ok(message) if message.len() == key_len => Ok(message),
        _ => Ok(fallback),
    }
}

#[cfg(not(feature = "aws-lc-rs"))]
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

#[cfg(not(feature = "aws-lc-rs"))]
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

pub(crate) type Private = rsa::PrivateKey;
#[cfg(not(feature = "aws-lc-rs"))]
pub(crate) type Public = rsa::PublicKey;

pub(super) fn generate(bits: usize) -> anyhow::Result<Private> {
    if !(rsa::PublicKey::MIN_SIZE..=rsa::PublicKey::MAX_SIZE).contains(&bits) {
        bail!("Unsupported RSA modulus length: {bits} bits.");
    }
    Ok(Private::new(&mut SysRng, bits)?)
}

pub(super) fn size(key: &Private) -> usize {
    use rsa::traits::PublicKeyParts;
    key.size()
}

#[cfg(not(feature = "aws-lc-rs"))]
pub(super) fn public_size(key: &Public) -> usize {
    use rsa::traits::PublicKeyParts;
    key.size()
}

#[cfg(not(feature = "aws-lc-rs"))]
pub(super) fn to_public(key: &Private) -> anyhow::Result<Public> {
    Ok(key.to_public_key())
}

pub(super) fn export_private(key: &Private) -> anyhow::Result<Vec<u8>> {
    use rsa::pkcs1::EncodeRsaPrivateKey;
    Ok(key.to_pkcs1_der()?.as_bytes().to_vec())
}

#[cfg(not(feature = "aws-lc-rs"))]
pub(super) fn export_public(key: &Public) -> anyhow::Result<Vec<u8>> {
    use rsa::pkcs1::EncodeRsaPublicKey;
    Ok(key.to_pkcs1_der()?.into_vec())
}

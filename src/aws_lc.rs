use std::num::NonZeroU32;

use anyhow::bail;
use aws_lc_rs::{aead, cipher, hmac, key_wrap, pbkdf2};

use crate::util::HashAlgorithm;

fn gcm_key(key: &[u8]) -> anyhow::Result<aead::LessSafeKey> {
    let algorithm = match key.len() {
        16 => &aead::AES_128_GCM,
        24 => &aead::AES_192_GCM,
        32 => &aead::AES_256_GCM,
        _ => bail!("Invalid AES-GCM key length."),
    };
    Ok(aead::LessSafeKey::new(aead::UnboundKey::new(
        algorithm, key,
    )?))
}

pub(crate) fn encrypt_gcm(
    key: &[u8],
    iv: &[u8; 12],
    aad: &[u8],
    message: &[u8],
) -> anyhow::Result<(Vec<u8>, [u8; 16])> {
    let key = gcm_key(key)?;
    let nonce = aead::Nonce::assume_unique_for_key(*iv);
    let mut ciphertext = message.to_vec();
    let tag = key.seal_in_place_separate_tag(nonce, aead::Aad::from(aad), &mut ciphertext)?;
    Ok((ciphertext, tag.as_ref().try_into()?))
}

pub(crate) fn decrypt_gcm(
    key: &[u8],
    iv: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if tag.len() != 16 {
        bail!("The AES-GCM tag must be 16 bytes.");
    }
    let key = gcm_key(key)?;
    let nonce = aead::Nonce::assume_unique_for_key(*iv);
    let mut message = Vec::with_capacity(ciphertext.len() + tag.len());
    message.extend_from_slice(ciphertext);
    message.extend_from_slice(tag);
    let len = key
        .open_in_place(nonce, aead::Aad::from(aad), &mut message)?
        .len();
    message.truncate(len);
    Ok(message)
}

fn cbc_key(key: &[u8]) -> anyhow::Result<cipher::UnboundCipherKey> {
    let algorithm = match key.len() {
        16 => &cipher::AES_128,
        24 => &cipher::AES_192,
        32 => &cipher::AES_256,
        _ => bail!("Invalid AES-CBC key length."),
    };
    Ok(cipher::UnboundCipherKey::new(algorithm, key)?)
}

pub(crate) fn encrypt_cbc(key: &[u8], iv: &[u8], message: &[u8]) -> anyhow::Result<Vec<u8>> {
    let encrypting_key = cipher::PaddedBlockEncryptingKey::cbc_pkcs7(cbc_key(key)?)?;
    let mut ciphertext = message.to_vec();
    encrypting_key.less_safe_encrypt(
        &mut ciphertext,
        cipher::EncryptionContext::Iv128(iv.try_into()?),
    )?;
    Ok(ciphertext)
}

pub(crate) fn decrypt_cbc(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let decrypting_key = cipher::PaddedBlockDecryptingKey::cbc_pkcs7(cbc_key(key)?)?;
    let mut message = ciphertext.to_vec();
    let len = decrypting_key
        .decrypt(
            &mut message,
            cipher::DecryptionContext::Iv128(iv.try_into()?),
        )?
        .len();
    message.truncate(len);
    Ok(message)
}

pub(crate) fn sign_hmac(
    hash: HashAlgorithm,
    key: &[u8],
    parts: &[&[u8]],
) -> anyhow::Result<Vec<u8>> {
    let algorithm = match hash {
        HashAlgorithm::Sha256 => hmac::HMAC_SHA256,
        HashAlgorithm::Sha384 => hmac::HMAC_SHA384,
        HashAlgorithm::Sha512 => hmac::HMAC_SHA512,
        HashAlgorithm::Sha1 => bail!("SHA-1 is unsupported for JOSE HMAC."),
    };
    let key = hmac::Key::new(algorithm, key);
    let mut context = hmac::Context::with_key(&key);
    for part in parts {
        context.update(part);
    }
    Ok(context.sign().as_ref().to_vec())
}

pub(crate) fn derive_pbkdf2(
    hash: HashAlgorithm,
    password: &[u8],
    salt: &[u8],
    rounds: usize,
    out: &mut [u8],
) -> anyhow::Result<()> {
    let algorithm = match hash {
        HashAlgorithm::Sha256 => pbkdf2::PBKDF2_HMAC_SHA256,
        HashAlgorithm::Sha384 => pbkdf2::PBKDF2_HMAC_SHA384,
        HashAlgorithm::Sha512 => pbkdf2::PBKDF2_HMAC_SHA512,
        HashAlgorithm::Sha1 => bail!("SHA-1 is unsupported for JOSE PBKDF2."),
    };
    let rounds = NonZeroU32::try_from(i32::try_from(rounds)? as u32)?;
    pbkdf2::derive(algorithm, rounds, salt, password, out);
    Ok(())
}

pub(crate) fn key_wrap_key(key: &[u8]) -> anyhow::Result<key_wrap::AesKek> {
    let algorithm = match key.len() {
        16 => &key_wrap::AES_128,
        32 => &key_wrap::AES_256,
        _ => bail!("Invalid AWS-LC AES Key Wrap key size."),
    };
    Ok(key_wrap::AesKek::new(algorithm, key)?)
}

pub(crate) fn sha256(parts: &[&[u8]]) -> aws_lc_rs::digest::Digest {
    let mut context = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    for part in parts {
        context.update(part);
    }
    context.finish()
}

pub(crate) fn derive(
    algorithm: &'static aws_lc_rs::agreement::Algorithm,
    private: &[u8],
    public: &[u8],
) -> anyhow::Result<Vec<u8>> {
    use aws_lc_rs::{agreement, error::Unspecified};

    let key = agreement::PrivateKey::from_private_key(algorithm, private)?;
    let peer = agreement::UnparsedPublicKey::new(algorithm, public);
    Ok(agreement::agree(&key, peer, Unspecified, |secret| {
        Ok(secret.to_vec())
    })?)
}

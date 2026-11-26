use std::fmt::Display;
use std::ops::Deref;

use anyhow::bail;
#[cfg(not(any(feature = "aes-gcm-rustcrypto", feature = "aws-lc-rs")))]
use openssl::symm::{self, Cipher};

use crate::jwe::JweContentEncryption;
use crate::JoseError;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AesgcmJweEncryption {
    /// AES GCM using 128-bit key
    A128gcm,
    /// AES GCM using 192-bit key
    A192gcm,
    /// AES GCM using 256-bit key
    A256gcm,
}

impl JweContentEncryption for AesgcmJweEncryption {
    fn name(&self) -> &str {
        match self {
            Self::A128gcm => "A128GCM",
            Self::A192gcm => "A192GCM",
            Self::A256gcm => "A256GCM",
        }
    }

    fn key_len(&self) -> usize {
        match self {
            Self::A128gcm => 16,
            Self::A192gcm => 24,
            Self::A256gcm => 32,
        }
    }

    fn iv_len(&self) -> usize {
        12
    }

    fn encrypt(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        message: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), JoseError> {
        (|| -> anyhow::Result<(Vec<u8>, Option<Vec<u8>>)> {
            let expected_len = self.key_len();
            if key.len() != expected_len {
                bail!(
                    "The length of content encryption key must be {}: {}",
                    expected_len,
                    key.len()
                );
            }

            let (encrypted_message, tag) = encrypt_aead(key, iv, aad, message)?;
            Ok((encrypted_message, Some(tag.to_vec())))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn decrypt(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        encrypted_message: &[u8],
        aad: &[u8],
        tag: Option<&[u8]>,
    ) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let expected_len = self.key_len();
            if key.len() != expected_len {
                bail!(
                    "The length of content encryption key must be {}: {}",
                    expected_len,
                    key.len()
                );
            }

            let tag = match tag {
                Some(val) => val,
                None => bail!("A tag value is required."),
            };

            decrypt_aead(key, iv, aad, encrypted_message, tag)
        })()
        .map_err(|err| JoseError::InvalidJweFormat(err))
    }

    fn box_clone(&self) -> Box<dyn JweContentEncryption> {
        Box::new(self.clone())
    }
}

#[cfg(all(feature = "aes-gcm-rustcrypto", not(feature = "aws-lc-rs")))]
macro_rules! with_cipher {
    ($key:expr, |$cipher:ident| $operation:expr) => {{
        use aes_gcm::{aes, Aes128Gcm, Aes256Gcm, AesGcm, KeyInit};
        type Aes192Gcm = AesGcm<aes::Aes192, aes::cipher::consts::U12>;

        match $key.len() {
            16 => {
                let $cipher = Aes128Gcm::new_from_slice($key).unwrap();
                $operation
            }
            24 => {
                let $cipher = Aes192Gcm::new_from_slice($key).unwrap();
                $operation
            }
            32 => {
                let $cipher = Aes256Gcm::new_from_slice($key).unwrap();
                $operation
            }
            _ => bail!("Invalid AES-GCM key length."),
        }
    }};
}

pub(crate) fn encrypt_aead(
    key: &[u8],
    iv: Option<&[u8]>,
    aad: &[u8],
    message: &[u8],
) -> anyhow::Result<(Vec<u8>, [u8; 16])> {
    #[cfg(feature = "aws-lc-rs")]
    return crate::aws_lc::encrypt_gcm(key, iv, aad, message);
    #[cfg(not(any(feature = "aes-gcm-rustcrypto", feature = "aws-lc-rs")))]
    {
        let mut tag = [0; 16];
        let ciphertext = symm::encrypt_aead(cipher(key.len())?, key, iv, aad, message, &mut tag)?;
        Ok((ciphertext, tag))
    }
    #[cfg(all(feature = "aes-gcm-rustcrypto", not(feature = "aws-lc-rs")))]
    {
        use aes_gcm::aead::AeadInOut;

        let nonce = iv
            .unwrap_or_default()
            .try_into()
            .map_err(|_| anyhow::anyhow!("The AES-GCM IV must be 12 bytes."))?;
        let mut ciphertext = message.to_vec();
        let tag = with_cipher!(key, |cipher| {
            cipher.encrypt_inout_detached(nonce, aad, ciphertext.as_mut_slice().into())
        })
        .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed."))?;
        Ok((ciphertext, tag.into()))
    }
}

pub(crate) fn decrypt_aead(
    key: &[u8],
    iv: Option<&[u8]>,
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if tag.len() != 16 {
        bail!("The AES-GCM tag must be 16 bytes.");
    }

    #[cfg(feature = "aws-lc-rs")]
    return crate::aws_lc::decrypt_gcm(key, iv, aad, ciphertext, tag);
    #[cfg(not(any(feature = "aes-gcm-rustcrypto", feature = "aws-lc-rs")))]
    {
        Ok(symm::decrypt_aead(
            cipher(key.len())?,
            key,
            iv,
            aad,
            ciphertext,
            tag,
        )?)
    }
    #[cfg(all(feature = "aes-gcm-rustcrypto", not(feature = "aws-lc-rs")))]
    {
        use aes_gcm::aead::AeadInOut;

        let nonce = iv
            .unwrap_or_default()
            .try_into()
            .map_err(|_| anyhow::anyhow!("The AES-GCM IV must be 12 bytes."))?;
        let tag = tag
            .try_into()
            .map_err(|_| anyhow::anyhow!("The AES-GCM tag must be 16 bytes."))?;
        let mut message = ciphertext.to_vec();
        with_cipher!(key, |cipher| {
            cipher.decrypt_inout_detached(nonce, aad, message.as_mut_slice().into(), tag)
        })
        .map_err(|_| anyhow::anyhow!("AES-GCM authentication failed."))?;
        Ok(message)
    }
}

#[cfg(not(any(feature = "aes-gcm-rustcrypto", feature = "aws-lc-rs")))]
fn cipher(key_len: usize) -> anyhow::Result<Cipher> {
    match key_len {
        16 => Ok(Cipher::aes_128_gcm()),
        24 => Ok(Cipher::aes_192_gcm()),
        32 => Ok(Cipher::aes_256_gcm()),
        _ => bail!("Invalid AES-GCM key length."),
    }
}

impl Display for AesgcmJweEncryption {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for AesgcmJweEncryption {
    type Target = dyn JweContentEncryption;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::AesgcmJweEncryption;
    use crate::util;
    use crate::JoseError;

    #[test]
    fn encrypt_and_decrypt_aes_gcm() -> Result<()> {
        let message = b"abcde12345";
        let aad = b"test";

        for enc in vec![
            AesgcmJweEncryption::A128gcm,
            AesgcmJweEncryption::A192gcm,
            AesgcmJweEncryption::A256gcm,
        ] {
            let key = util::random_bytes(enc.key_len());
            let iv = util::random_bytes(enc.iv_len());

            let (encrypted_message, tag) = enc.encrypt(&key, Some(&iv), message, aad)?;
            let decrypted_message = enc.decrypt(
                &key,
                Some(&iv),
                &encrypted_message,
                &aad[..],
                tag.as_deref(),
            )?;

            assert_eq!(&message[..], &decrypted_message[..]);

            for tag_len in [0, 1, 4, 15, 17] {
                let invalid_tag = &[0; 17][..tag_len];
                let result =
                    enc.decrypt(&key, Some(&iv), &encrypted_message, aad, Some(invalid_tag));
                assert!(
                    matches!(result, Err(JoseError::InvalidJweFormat(err)) if err.to_string() == "The AES-GCM tag must be 16 bytes."),
                    "{enc} must reject a {tag_len}-byte tag before authentication"
                );
            }
        }

        Ok(())
    }
}

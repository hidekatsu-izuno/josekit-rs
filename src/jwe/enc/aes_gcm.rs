use std::fmt::Display;
use std::ops::Deref;

use anyhow::bail;
use openssl::symm::{self, Cipher};

use crate::jose::JoseError;
use crate::jwe::JweContentEncryption;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AesGcmJweEncryption {
    /// AES GCM using 128-bit key
    A128Gcm,
    /// AES GCM using 192-bit key
    A192Gcm,
    /// AES GCM using 256-bit key
    A256Gcm,
}

impl AesGcmJweEncryption {
    fn cipher(&self) -> Cipher {
        match self {
            Self::A128Gcm => Cipher::aes_128_gcm(),
            Self::A192Gcm => Cipher::aes_192_gcm(),
            Self::A256Gcm => Cipher::aes_256_gcm(),
        }
    }
}

impl JweContentEncryption for AesGcmJweEncryption {
    fn name(&self) -> &str {
        match self {
            Self::A128Gcm => "A128GCM",
            Self::A192Gcm => "A192GCM",
            Self::A256Gcm => "A256GCM",
        }
    }

    fn key_len(&self) -> usize {
        match self {
            Self::A128Gcm => 16,
            Self::A192Gcm => 24,
            Self::A256Gcm => 32,
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

            let cipher = self.cipher();
            let mut tag = [0; 16];
            let encrypted_message = symm::encrypt_aead(cipher, key, iv, aad, message, &mut tag)?;
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

            let cipher = self.cipher();
            let message = symm::decrypt_aead(cipher, key, iv, aad, encrypted_message, tag)?;
            Ok(message)
        })()
        .map_err(|err| JoseError::InvalidJweFormat(err))
    }

    fn box_clone(&self) -> Box<dyn JweContentEncryption> {
        Box::new(self.clone())
    }
}

impl Display for AesGcmJweEncryption {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for AesGcmJweEncryption {
    type Target = dyn JweContentEncryption;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use openssl::rand;

    use super::AesGcmJweEncryption;

    #[test]
    fn encrypt_and_decrypt_aes_gcm() -> Result<()> {
        let message = b"abcde12345";
        let aad = b"test";

        for enc in vec![
            AesGcmJweEncryption::A128Gcm,
            AesGcmJweEncryption::A192Gcm,
            AesGcmJweEncryption::A256Gcm,
        ] {
            let mut key = vec![0; enc.key_len()];
            rand::rand_bytes(&mut key)?;

            let mut iv = vec![0; enc.iv_len()];
            rand::rand_bytes(&mut iv)?;

            let (encrypted_message, tag) = enc.encrypt(&key, Some(&iv), message, aad)?;
            let decrypted_message = enc.decrypt(
                &key, 
                Some(&iv), 
                &encrypted_message, 
                &aad[..], 
                tag.as_deref()
            )?;

            assert_eq!(&message[..], &decrypted_message[..]);
        }
        
        Ok(())
    }
}

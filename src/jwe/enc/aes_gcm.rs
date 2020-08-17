use openssl::symm::{self, Cipher};

use crate::jwe::JweContentEncryption;
use crate::jose::JoseError;

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

    fn iv_len(&self) -> usize {
        12
    }

    fn enc_key_len(&self) -> usize {
        16
    }

    fn mac_key_len(&self) -> usize {
        0
    }

    fn encrypt(&self, message: &[u8], iv: &[u8], enc_key: &[u8]) -> Result<Vec<u8>, JoseError> {
        let cipher = self.cipher();

        (|| -> anyhow::Result<Vec<u8>> {
            let encrypted = symm::encrypt(cipher, enc_key, Some(iv), message)?;
            Ok(encrypted)
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn decrypt(&self, data: &[u8], iv: &[u8], enc_key: &[u8]) -> Result<Vec<u8>, JoseError> {
        let cipher = self.cipher();

        (|| -> anyhow::Result<Vec<u8>> {
            let decrypted = symm::decrypt(cipher, enc_key, Some(iv), data)?;
            Ok(decrypted)
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }
    
    fn sign(&self, _message: Vec<&[u8]>, _mac_key: &[u8]) -> Result<Vec<u8>, JoseError> {
        unimplemented!("AES GCM doesn't need to sign.");
    }

    fn box_clone(&self) -> Box<dyn JweContentEncryption> {
        Box::new(self.clone())
    }
}

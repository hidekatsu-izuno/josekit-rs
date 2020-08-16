use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::symm::{self, Cipher};
use openssl::sign::Signer;

use crate::jwe::JweContentEncryption;
use crate::jose::JoseError;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AesCbcHmacJweEncryption {
    /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm
    A128CbcHS256,
    /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm
    A192CbcHS384,
    /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm
    A256CbcHS512,
}

impl AesCbcHmacJweEncryption {
    fn cipher(&self) -> Cipher {
        match self {
            Self::A128CbcHS256 => Cipher::aes_128_cbc(),
            Self::A192CbcHS384 => Cipher::aes_192_cbc(),
            Self::A256CbcHS512 => Cipher::aes_256_cbc(),
        }
    }
}

impl JweContentEncryption for AesCbcHmacJweEncryption {
    fn name(&self) -> &str {
        match self {
            Self::A128CbcHS256 => "A128CBC-HS256",
            Self::A192CbcHS384 => "A192CBC-HS384",
            Self::A256CbcHS512 => "A256CBC-HS512",
        }
    }
    
    fn encrypted_len(&self, len: usize) -> usize {
        (len + (16 - 1) / 16) * 16
    }

    fn iv_len(&self) -> usize {
        16
    }
    
    fn enc_key_len(&self) -> usize {
        16
    }

    fn mac_key_len(&self) -> usize {
        match self {
            Self::A128CbcHS256 => 16,
            Self::A192CbcHS384 => 24,
            Self::A256CbcHS512 => 32,
        }
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

    fn sign(&self, message: Vec<&[u8]>, mac_key: &[u8]) -> Result<Vec<u8>, JoseError> {
        let message_digest = match self {
            Self::A128CbcHS256 => MessageDigest::sha256(),
            Self::A192CbcHS384 => MessageDigest::sha384(),
            Self::A256CbcHS512 => MessageDigest::sha512(),
        };

        let pkey = (|| -> anyhow::Result<PKey<Private>> {
            let pkey = PKey::hmac(mac_key)?;
            Ok(pkey)
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))?;

        let signature = (|| -> anyhow::Result<Vec<u8>> {
            let mut signer = Signer::new(message_digest, &pkey)?;
            for seg in message {
                signer.update(seg)?;
            }
            let signature = signer.sign_to_vec()?;
            Ok(signature)
        })()
        .map_err(|err| JoseError::InvalidSignature(err))?;

        Ok(signature)
    }

    fn box_clone(&self) -> Box<dyn JweContentEncryption> {
        Box::new(self.clone())
    }
}

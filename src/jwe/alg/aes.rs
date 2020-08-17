use crate::jose::JoseError;
use crate::jwe::{JweAlgorithm, JweDecrypter, JweEncrypter};
use crate::jwk::Jwk;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AesJweAlgorithm {
    /// AES Key Wrap with default initial value using 128-bit key
    A128Kw,
    /// AES Key Wrap with default initial value using 192-bit key
    A192Kw,
    /// AES Key Wrap with default initial value using 256-bit key
    A256Kw,
}

impl AesJweAlgorithm {
    pub fn encrypter_from_jwk(&self, jwk: &Jwk) -> Result<AesJweEncrypter, JoseError> {
        todo!();
    }

    pub fn decrypter_from_jwk(&self, jwk: &Jwk) -> Result<AesJweDecrypter, JoseError> {
        todo!();
    }
}

impl JweAlgorithm for AesJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::A128Kw => "A128KW",
            Self::A192Kw => "A192KW",
            Self::A256Kw => "A256KW",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AesJweEncrypter {
    algorithm: AesJweAlgorithm,
    key_id: Option<String>,
}

impl JweEncrypter for AesJweEncrypter {
    fn algorithm(&self) -> &dyn JweAlgorithm {
        &self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn set_key_id(&mut self, key_id: &str) {
        self.key_id = Some(key_id.to_string());
    }

    fn remove_key_id(&mut self) {
        self.key_id = None;
    }

    fn content_encryption_key(&self) -> Option<&[u8]> {
        None
    }

    fn encrypt(&self, content_encryption_key: &[u8]) -> Result<Option<Vec<u8>>, JoseError> {
        todo!();
    }
}

#[derive(Debug, Clone)]
pub struct AesJweDecrypter {
    algorithm: AesJweAlgorithm,
    key_id: Option<String>,
}

impl JweDecrypter for AesJweDecrypter {
    fn algorithm(&self) -> &dyn JweAlgorithm {
        &self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn set_key_id(&mut self, key_id: &str) {
        self.key_id = Some(key_id.to_string());
    }

    fn remove_key_id(&mut self) {
        self.key_id = None;
    }

    fn content_encryption_key(&self) -> Option<&[u8]> {
        None
    }

    fn decrypt(&self, encrypted_key: &[u8]) -> Result<Option<Vec<u8>>, JoseError> {
        todo!();
    }
}

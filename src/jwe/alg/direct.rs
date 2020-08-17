use crate::jose::JoseError;
use crate::jwe::{JweAlgorithm, JweDecrypter, JweEncrypter};
use crate::jwk::Jwk;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum DirectJweAlgorithm {
    /// Direct use of a shared symmetric key as the CEK
    Dir,
}

impl DirectJweAlgorithm {
    pub fn encrypter_from_jwk(&self, jwk: &Jwk) -> Result<DirectJweEncrypter, JoseError> {
        unimplemented!();
    }

    pub fn decrypter_from_jwk(&self, jwk: &Jwk) -> Result<DirectJweDecrypter, JoseError> {
        unimplemented!();
    }
}

impl JweAlgorithm for DirectJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::Dir => "dir",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DirectJweEncrypter {
    algorithm: DirectJweAlgorithm,
    key_id: Option<String>,
    content_encryption_key: Vec<u8>,
}

impl JweEncrypter for DirectJweEncrypter {
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
        Some(&self.content_encryption_key)
    }

    fn encrypt_key(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, JoseError> {
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct DirectJweDecrypter {
    algorithm: DirectJweAlgorithm,
    key_id: Option<String>,
    content_encryption_key: Vec<u8>,
}

impl JweDecrypter for DirectJweDecrypter {
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
        Some(&self.content_encryption_key)
    }

    fn decrypt_key(&self, _encrypted_key: &[u8]) -> Result<Option<Vec<u8>>, JoseError> {
        Ok(None)
    }
}


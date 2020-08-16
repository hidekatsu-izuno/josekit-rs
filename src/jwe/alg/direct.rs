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
}

impl JweEncrypter for DirectJweEncrypter {
    fn algorithm(&self) -> &dyn JweAlgorithm {
        &self.algorithm
    }

    fn encrypted_len(&self, len: usize) -> usize {
        len
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

    fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, JoseError> {
        Ok(message.to_vec())
    }
}

#[derive(Debug, Clone)]
pub struct DirectJweDecrypter {
    algorithm: DirectJweAlgorithm,
    key_id: Option<String>,
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

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, JoseError> {
        Ok(data.to_vec())
    }
}


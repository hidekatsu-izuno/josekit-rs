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
pub struct DirectJweEncrypter;

#[derive(Debug, Clone)]
pub struct DirectJweDecrypter;

use crate::jose::JoseError;
use crate::jwe::{JweAlgorithm, JweDecrypter, JweEncrypter, JweEncryption};
use crate::jwk::Jwk;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum DirJweAlgorithm {
    /// Direct use of a shared symmetric key as the CEK
    Dir,
}

impl DirJweAlgorithm {
    pub fn encrypter_from_jwk(
        &self,
        jwk: &Jwk,
        encryption: &dyn JweEncryption,
    ) -> Result<DirJweEncrypter, JoseError> {
        unimplemented!();
    }

    pub fn decrypter_from_jwk(
        &self,
        jwk: &Jwk,
        encryption: &dyn JweEncryption,
    ) -> Result<DirJweDecrypter, JoseError> {
        unimplemented!();
    }
}

impl JweAlgorithm for DirJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::Dir => "dir",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DirJweEncrypter;

#[derive(Debug, Clone)]
pub struct DirJweDecrypter;

use crate::jose::JoseError;
use crate::jwe::{JweAlgorithm, JweDecrypter, JweEncrypter, JweEncryption};
use crate::jwk::Jwk;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AesJweAlgorithm {
    /// AES Key Wrap with default initial value using 128-bit key
    A128KW,
    /// AES Key Wrap with default initial value using 192-bit key
    A192KW,
    /// AES Key Wrap with default initial value using 256-bit key
    A256KW,
}

impl AesJweAlgorithm {
    pub fn encrypter_from_jwk(
        &self,
        jwk: &Jwk,
        encryption: &dyn JweEncryption,
    ) -> Result<AesJweEncrypter, JoseError> {
        unimplemented!();
    }

    pub fn decrypter_from_jwk(
        &self,
        jwk: &Jwk,
        encryption: &dyn JweEncryption,
    ) -> Result<AesJweDecrypter, JoseError> {
        unimplemented!();
    }
}

impl JweAlgorithm for AesJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::A128KW => "A128KW",
            Self::A192KW => "A192KW",
            Self::A256KW => "A256KW",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AesJweEncrypter;

#[derive(Debug, Clone)]
pub struct AesJweDecrypter;

use crate::jwe::{JweAlgorithm, JweEncryption, JweEncrypter, JweDecrypter};
use crate::jwk::Jwk;
use crate::error::JoseError;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AesJweAlgorithm {
    /// AES Key Wrap with default initial value using 128-bit key
    A128KW,
    /// AES Key Wrap with default initial value using 192-bit key
    A192KW,
    /// AES Key Wrap with default initial value using 256-bit key
    A256KW,
}

impl JweAlgorithm for AesJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::A128KW => "A128KW",
            Self::A192KW => "A192KW",
            Self::A256KW => "A256KW",
        }
    }

    fn encrypter_from_jwk(&self, jwk: &Jwk, encryption: &dyn JweEncryption) -> Result<Box<dyn JweEncrypter>, JoseError> {
        unimplemented!();
    }

    fn decrypter_from_jwk(&self, jwk: &Jwk, encryption: &dyn JweEncryption) -> Result<Box<dyn JweDecrypter>, JoseError> {
        unimplemented!();
    }
}

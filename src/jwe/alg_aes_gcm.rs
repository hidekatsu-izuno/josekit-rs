use crate::jwe::{JweAlgorithm, JweEncryption, JweEncrypter, JweDecrypter};
use crate::jwk::Jwk;
use crate::error::JoseError;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AesGcmJweAlgorithm {
    /// Key wrapping with AES GCM using 128-bit key
    A128GCMKW,
    /// Key wrapping with AES GCM using 192-bit key
    A192GCMKW,
    /// Key wrapping with AES GCM using 256-bit key
    A256GCMKW,
}

impl JweAlgorithm for AesGcmJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::A128GCMKW => "A128GCMKW",
            Self::A192GCMKW => "A192GCMKW",
            Self::A256GCMKW => "A256GCMKW",
        }
    }

    fn encrypter_from_jwk(&self, jwk: &Jwk, encryption: &dyn JweEncryption) -> Result<Box<dyn JweEncrypter>, JoseError> {
        unimplemented!();
    }

    fn decrypter_from_jwk(&self, jwk: &Jwk, encryption: &dyn JweEncryption) -> Result<Box<dyn JweDecrypter>, JoseError> {
        unimplemented!();
    }
}
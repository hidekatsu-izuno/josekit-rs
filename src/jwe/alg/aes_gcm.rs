use crate::jose::JoseError;
use crate::jwe::{JweAlgorithm, JweDecrypter, JweEncrypter, JweEncryption};
use crate::jwk::Jwk;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AesGcmJweAlgorithm {
    /// Key wrapping with AES GCM using 128-bit key
    A128GcmKw,
    /// Key wrapping with AES GCM using 192-bit key
    A192GcmKw,
    /// Key wrapping with AES GCM using 256-bit key
    A256GcmKw,
}

impl AesGcmJweAlgorithm {
    pub fn encrypter_from_jwk(
        &self,
        jwk: &Jwk,
        encryption: &dyn JweEncryption,
    ) -> Result<AesGcmJweEncrypter, JoseError> {
        unimplemented!();
    }

    pub fn decrypter_from_jwk(
        &self,
        jwk: &Jwk,
        encryption: &dyn JweEncryption,
    ) -> Result<AesGcmJweDecrypter, JoseError> {
        unimplemented!();
    }
}

impl JweAlgorithm for AesGcmJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::A128GcmKw => "A128GCMKW",
            Self::A192GcmKw => "A192GCMKW",
            Self::A256GcmKw => "A256GCMKW",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AesGcmJweEncrypter;

#[derive(Debug, Clone)]
pub struct AesGcmJweDecrypter;

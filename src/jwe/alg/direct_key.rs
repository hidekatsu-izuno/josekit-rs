use crate::jose::JoseError;
use crate::jwe::{JweAlgorithm, JweDecrypter, JweEncrypter};
use crate::jwk::Jwk;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum DirectKeyJweAlgorithm {
    /// Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF
    EcdhEs,
}

impl DirectKeyJweAlgorithm {
    pub fn encrypter_from_jwk(&self, jwk: &Jwk) -> Result<DirectKeyJweAlgorithm, JoseError> {
        unimplemented!();
    }

    pub fn decrypter_from_jwk(&self, jwk: &Jwk) -> Result<DirectKeyJweAlgorithm, JoseError> {
        unimplemented!();
    }
}

impl JweAlgorithm for DirectKeyJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::EcdhEs => "ECDH-ES",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DirectKeyJweEncrypter;

#[derive(Debug, Clone)]
pub struct DirectKeyJweDecrypter;

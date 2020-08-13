use crate::jose::JoseError;
use crate::jwe::{JweAlgorithm, JweDecrypter, JweEncrypter};
use crate::jwk::Jwk;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum RsaesJweAlgorithm {
    /// RSAES-PKCS1-v1_5
    Rsa1_5,
    /// RSAES OAEP using default parameters
    RsaOaep,
    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
    RsaOaep256,
}

impl RsaesJweAlgorithm {
    pub fn encrypter_from_jwk(&self, jwk: &Jwk) -> Result<RsaesJweEncrypter, JoseError> {
        unimplemented!();
    }

    pub fn decrypter_from_jwk(&self, jwk: &Jwk) -> Result<RsaesJweDecrypter, JoseError> {
        unimplemented!();
    }
}

impl JweAlgorithm for RsaesJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::Rsa1_5 => "RSA1_5",
            Self::RsaOaep => "RSA-OAEP",
            Self::RsaOaep256 => "RSA-OAEP-256",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RsaesJweEncrypter;

#[derive(Debug, Clone)]
pub struct RsaesJweDecrypter;

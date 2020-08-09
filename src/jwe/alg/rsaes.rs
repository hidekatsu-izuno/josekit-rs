use crate::error::JoseError;
use crate::jwe::{JweAlgorithm, JweDecrypter, JweEncrypter, JweEncryption};
use crate::jwk::Jwk;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum RsaesJweAlgorithm {
    /// RSAES-PKCS1-v1_5
    RSA1_5,
    /// RSAES OAEP using default parameters
    RSA_OAEP,
    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
    RSA_OAEP_256,
}

impl RsaesJweAlgorithm {
    pub fn encrypter_from_jwk(
        &self,
        jwk: &Jwk,
        encryption: &dyn JweEncryption,
    ) -> Result<RsaesJweEncrypter, JoseError> {
        unimplemented!();
    }

    pub fn decrypter_from_jwk(
        &self,
        jwk: &Jwk,
        encryption: &dyn JweEncryption,
    ) -> Result<RsaesJweDecrypter, JoseError> {
        unimplemented!();
    }
}

impl JweAlgorithm for RsaesJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::RSA1_5 => "RSA1_5",
            Self::RSA_OAEP => "RSA-OAEP",
            Self::RSA_OAEP_256 => "RSA-OAEP-256",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RsaesJweEncrypter;

#[derive(Debug, Clone)]
pub struct RsaesJweDecrypter;

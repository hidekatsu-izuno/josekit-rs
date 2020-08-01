use crate::jwe::{JweAlgorithm, JweEncryption, JweEncrypter, JweDecrypter};
use crate::jwk::Jwk;
use crate::error::JoseError;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum RsaesJweAlgorithm {
    /// RSAES-PKCS1-v1_5
    RSA1_5,
    /// RSAES OAEP using default parameters
    RSA_OAEP,
    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
    RSA_OAEP_256,
}

impl JweAlgorithm for RsaesJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::RSA1_5 => "RSA1_5",
            Self::RSA_OAEP => "RSA-OAEP",
            Self::RSA_OAEP_256 => "RSA-OAEP-256",
        }
    }

    fn encrypter_from_jwk(&self, jwk: &Jwk, encryption: &dyn JweEncryption) -> Result<Box<dyn JweEncrypter>, JoseError> {
        unimplemented!();
    }

    fn decrypter_from_jwk(&self, jwk: &Jwk, encryption: &dyn JweEncryption) -> Result<Box<dyn JweDecrypter>, JoseError> {
        unimplemented!();
    }
}

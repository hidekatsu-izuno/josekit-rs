use crate::jwe::{JweAlgorithm, JweEncryption, JweEncrypter, JweDecrypter};
use crate::jwk::Jwk;
use crate::error::JoseError;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum EcdhEsAesJweAlgorithm {
    /// ECDH-ES using Concat KDF and CEK wrapped with "A128KW" 
    ECDH_ES_A128KW,
    /// ECDH-ES using Concat KDF and CEK wrapped with "A192KW" 
    ECDH_ES_A192KW,
    /// ECDH-ES using Concat KDF and CEK wrapped with "A256KW" 
    ECDH_ES_A256KW,
}

impl JweAlgorithm for EcdhEsAesJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::ECDH_ES_A128KW => "ECDH-ES+A128KW",
            Self::ECDH_ES_A192KW => "ECDH-ES+A128KW",
            Self::ECDH_ES_A256KW => "ECDH-ES+A128KW",
        }
    }

    fn encrypter_from_jwk(&self, jwk: &Jwk, encryption: &dyn JweEncryption) -> Result<Box<dyn JweEncrypter>, JoseError> {
        unimplemented!();
    }

    fn decrypter_from_jwk(&self, jwk: &Jwk, encryption: &dyn JweEncryption) -> Result<Box<dyn JweDecrypter>, JoseError> {
        unimplemented!();
    }
}


use crate::error::JoseError;
use crate::jwe::{JweAlgorithm, JweDecrypter, JweEncrypter, JweEncryption};
use crate::jwk::Jwk;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum EcdhEsAesJweAlgorithm {
    /// ECDH-ES using Concat KDF and CEK wrapped with "A128KW"
    ECDH_ES_A128KW,
    /// ECDH-ES using Concat KDF and CEK wrapped with "A192KW"
    ECDH_ES_A192KW,
    /// ECDH-ES using Concat KDF and CEK wrapped with "A256KW"
    ECDH_ES_A256KW,
}

impl EcdhEsAesJweAlgorithm {
    pub fn encrypter_from_jwk(
        &self,
        jwk: &Jwk,
        encryption: &dyn JweEncryption,
    ) -> Result<EcdhEsAesJweEncrypter, JoseError> {
        unimplemented!();
    }

    pub fn decrypter_from_jwk(
        &self,
        jwk: &Jwk,
        encryption: &dyn JweEncryption,
    ) -> Result<EcdhEsAesJweDecrypter, JoseError> {
        unimplemented!();
    }
}

impl JweAlgorithm for EcdhEsAesJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::ECDH_ES_A128KW => "ECDH-ES+A128KW",
            Self::ECDH_ES_A192KW => "ECDH-ES+A128KW",
            Self::ECDH_ES_A256KW => "ECDH-ES+A128KW",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EcdhEsAesJweEncrypter;

#[derive(Debug, Clone)]
pub struct EcdhEsAesJweDecrypter;

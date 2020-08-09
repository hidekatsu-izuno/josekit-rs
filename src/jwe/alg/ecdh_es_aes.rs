use crate::jose::JoseError;
use crate::jwe::{JweAlgorithm, JweDecrypter, JweEncrypter, JweEncryption};
use crate::jwk::Jwk;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum EcdhEsAesJweAlgorithm {
    /// ECDH-ES using Concat KDF and CEK wrapped with "A128KW"
    EcdhEsA128Kw,
    /// ECDH-ES using Concat KDF and CEK wrapped with "A192KW"
    EcdhEsA192Kw,
    /// ECDH-ES using Concat KDF and CEK wrapped with "A256KW"
    EcdhEsA256Kw,
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
            Self::EcdhEsA128Kw => "ECDH-ES+A128KW",
            Self::EcdhEsA192Kw => "ECDH-ES+A192KW",
            Self::EcdhEsA256Kw => "ECDH-ES+A256KW",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EcdhEsAesJweEncrypter;

#[derive(Debug, Clone)]
pub struct EcdhEsAesJweDecrypter;

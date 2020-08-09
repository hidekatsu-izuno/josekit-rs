use crate::jose::JoseError;
use crate::jwe::{JweAlgorithm, JweDecrypter, JweEncrypter, JweEncryption};
use crate::jwk::Jwk;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Pbes2HmacAesJweAlgorithm {
    /// PBES2 with HMAC SHA-256 and "A128KW" wrapping
    Pbes2HS256A128Kw,
    /// PBES2 with HMAC SHA-384 and "A192KW" wrapping
    Pbes2HS384A192Kw,
    /// PBES2 with HMAC SHA-512 and "A256KW" wrapping
    Pbes2HS512A256Kw,
}

impl Pbes2HmacAesJweAlgorithm {
    pub fn encrypter_from_jwk(
        &self,
        jwk: &Jwk,
        encryption: &dyn JweEncryption,
    ) -> Result<Pbes2HmacAesJweEncrypter, JoseError> {
        unimplemented!();
    }

    pub fn decrypter_from_jwk(
        &self,
        jwk: &Jwk,
        encryption: &dyn JweEncryption,
    ) -> Result<Pbes2HmacAesJweDecrypter, JoseError> {
        unimplemented!();
    }
}

impl JweAlgorithm for Pbes2HmacAesJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::Pbes2HS256A128Kw => "PBES2-HS256+A128KW",
            Self::Pbes2HS384A192Kw => "PBES2-HS384+A192KW",
            Self::Pbes2HS512A256Kw => "PBES2-HS512+A256KW",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Pbes2HmacAesJweEncrypter;

#[derive(Debug, Clone)]
pub struct Pbes2HmacAesJweDecrypter;

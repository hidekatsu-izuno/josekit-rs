use crate::error::JoseError;
use crate::jwe::{JweAlgorithm, JweDecrypter, JweEncrypter, JweEncryption};
use crate::jwk::Jwk;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Pbes2HmacAesJweAlgorithm {
    /// PBES2 with HMAC SHA-256 and "A128KW" wrapping
    PBES2_HS256_A128KW,
    /// PBES2 with HMAC SHA-384 and "A192KW" wrapping
    PBES2_HS384_A192KW,
    /// PBES2 with HMAC SHA-512 and "A256KW" wrapping
    PBES2_HS512_A256KW,
}

impl JweAlgorithm for Pbes2HmacAesJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::PBES2_HS256_A128KW => "PBES2-HS256+A128KW",
            Self::PBES2_HS384_A192KW => "PBES2-HS384+A192KW",
            Self::PBES2_HS512_A256KW => "PBES2-HS512+A256KW",
        }
    }

    fn encrypter_from_jwk(
        &self,
        jwk: &Jwk,
        encryption: &dyn JweEncryption,
    ) -> Result<Box<dyn JweEncrypter>, JoseError> {
        unimplemented!();
    }

    fn decrypter_from_jwk(
        &self,
        jwk: &Jwk,
        encryption: &dyn JweEncryption,
    ) -> Result<Box<dyn JweDecrypter>, JoseError> {
        unimplemented!();
    }
}

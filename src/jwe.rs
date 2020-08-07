pub mod alg;
pub mod enc;

use std::collections::HashMap;
use std::fmt::Display;

use anyhow::bail;
use serde_json::{Map, Value};

use crate::error::JoseError;
use crate::jose::JoseHeader;
use crate::jwk::Jwk;
use crate::util::SourceValue;

pub use crate::jwe::alg::aes::AesJweAlgorithm::A128KW;
pub use crate::jwe::alg::aes::AesJweAlgorithm::A192KW;
pub use crate::jwe::alg::aes::AesJweAlgorithm::A256KW;

pub use crate::jwe::alg::aes_gcm::AesGcmJweAlgorithm::A128GCMKW;
pub use crate::jwe::alg::aes_gcm::AesGcmJweAlgorithm::A192GCMKW;
pub use crate::jwe::alg::aes_gcm::AesGcmJweAlgorithm::A256GCMKW;

pub use crate::jwe::alg::dir::DirJweAlgorithm::Dir;

pub use crate::jwe::alg::ecdh_es::EcdhEsJweAlgorithm::ECDH_ES;

pub use crate::jwe::alg::ecdh_es_aes::EcdhEsAesJweAlgorithm::ECDH_ES_A128KW;
pub use crate::jwe::alg::ecdh_es_aes::EcdhEsAesJweAlgorithm::ECDH_ES_A192KW;
pub use crate::jwe::alg::ecdh_es_aes::EcdhEsAesJweAlgorithm::ECDH_ES_A256KW;

pub use crate::jwe::alg::pbes2_hmac_aes::Pbes2HmacAesJweAlgorithm::PBES2_HS256_A128KW;
pub use crate::jwe::alg::pbes2_hmac_aes::Pbes2HmacAesJweAlgorithm::PBES2_HS384_A192KW;
pub use crate::jwe::alg::pbes2_hmac_aes::Pbes2HmacAesJweAlgorithm::PBES2_HS512_A256KW;

pub use crate::jwe::alg::rsaes::RsaesJweAlgorithm::RSA1_5;
pub use crate::jwe::alg::rsaes::RsaesJweAlgorithm::RSA_OAEP;
pub use crate::jwe::alg::rsaes::RsaesJweAlgorithm::RSA_OAEP_256;

pub use crate::jwe::enc::aes_cbc_hmac::AesCbcHmacJweEncryption::A128CBC_HS256;
pub use crate::jwe::enc::aes_cbc_hmac::AesCbcHmacJweEncryption::A192CBC_HS384;
pub use crate::jwe::enc::aes_cbc_hmac::AesCbcHmacJweEncryption::A256CBC_HS512;

pub use crate::jwe::enc::aes_gcm::AesGcmJweEncryption::A128GCM;
pub use crate::jwe::enc::aes_gcm::AesGcmJweEncryption::A192GCM;
pub use crate::jwe::enc::aes_gcm::AesGcmJweEncryption::A256GCM;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct JweHeader {
    claims: Map<String, Value>,
    sources: HashMap<String, SourceValue>,
}

impl JweHeader {
    pub fn new() -> Self {
        Self {
            claims: Map::new(),
            sources: HashMap::new(),
        }
    }

    /// Set a value for key ID header claim (kid).
    ///
    /// # Arguments
    /// * `value` - a key ID
    pub fn set_key_id(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("kid".to_string(), Value::String(value));
    }

    /// Return the value for key ID header claim (kid).
    pub fn key_id(&self) -> Option<&str> {
        match self.claims.get("kid") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }
}

impl JoseHeader for JweHeader {
    fn from_map(claims: Map<String, Value>) -> Result<Self, JoseError> {
        Ok(Self {
            claims,
            sources: HashMap::new(),
        })
    }

    fn claims_set(&self) -> &Map<String, Value> {
        &self.claims
    }

    fn set_claim(&mut self, key: &str, value: Option<Value>) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            match key {
                "alg" => bail!(
                    "The Unsecured {} header claim should not be setted expressly.",
                    key
                ),
                _ => match &value {
                    Some(_) => {
                        self.claims.insert(key.to_string(), value.unwrap());
                    }
                    None => {
                        self.claims.remove(key);
                    }
                },
            }

            Ok(())
        })()
        .map_err(|err| JoseError::InvalidJwtFormat(err))
    }
}

impl Display for JweHeader {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let val = serde_json::to_string(self.claims_set()).map_err(|_e| std::fmt::Error {})?;
        fmt.write_str(&val)
    }
}

pub trait JweAlgorithm {
    /// Return the "alg" (algorithm) header parameter value of JWE.
    fn name(&self) -> &str;

    /// Return the encrypter from a JWK private key.
    ///
    /// # Arguments
    /// * `jwk` - a JWK private key.
    /// * `encryption` - a JWE encryption algorithm.
    fn encrypter_from_jwk(
        &self,
        jwk: &Jwk,
        encryption: &dyn JweEncryption,
    ) -> Result<Box<dyn JweEncrypter>, JoseError>;

    /// Return the decrypter from a JWK key.
    ///
    /// # Arguments
    /// * `jwk` - a JWK key.
    /// * `encryption` - a JWE encryption algorithm.
    fn decrypter_from_jwk(
        &self,
        jwk: &Jwk,
        encryption: &dyn JweEncryption,
    ) -> Result<Box<dyn JweDecrypter>, JoseError>;
}

pub trait JweEncryption {
    /// Return the "enc" (encryption) header parameter value of JWE.
    fn name(&self) -> &str;

    fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, JoseError>;
}

pub trait JweEncrypter {
    /// Return the source algorithm instance.
    fn algorithm(&self) -> &dyn JweAlgorithm;

    /// Return the source key ID.
    /// The default value is a value of kid parameter in JWK.
    fn key_id(&self) -> Option<&str>;

    /// Set a compared value for a kid header claim (kid).
    ///
    /// # Arguments
    /// * `key_id` - a key ID
    fn set_key_id(&mut self, key_id: &str);

    /// Remove a compared value for a kid header claim (kid).
    fn remove_key_id(&mut self);

    /// Return a encypted key data.
    ///
    /// # Arguments
    /// * `key` - The key data to encrypt.
    fn encrypt(&self, key: &[u8]) -> Result<Vec<u8>, JoseError>;

    fn serialize_compact(&self, header: &JweHeader, payload: &[u8]) -> Result<String, JoseError> {
        (|| -> anyhow::Result<String> {
            let mut b64 = true;
            if let Some(Value::Bool(false)) = header.claim("b64") {
                if let Some(Value::Array(vals)) = header.claim("crit") {
                    if vals.iter().any(|e| e == "b64") {
                        b64 = false;
                    } else {
                        bail!("The b64 header claim name must be in critical.");
                    }
                }
            }
            Ok("".to_string())
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err),
        })
    }
}

pub trait JweDecrypter {
    /// Return the source algorithm instance.
    fn algorithm(&self) -> &dyn JweAlgorithm;

    /// Return the source key ID.
    /// The default value is a value of kid parameter in JWK.
    fn key_id(&self) -> Option<&str>;

    /// Set a compared value for a kid header claim (kid).
    ///
    /// # Arguments
    /// * `key_id` - a key ID
    fn set_key_id(&mut self, key_id: &str);

    /// Remove a compared value for a kid header claim (kid).
    fn remove_key_id(&mut self);

    /// Return a decypted key data.
    ///
    /// # Arguments
    /// * `key` - The encrypted key data.
    fn decrypt(&self, key: &[u8]) -> Result<Vec<u8>, JoseError>;

    fn deserialize_compact(&self, header: &JweHeader, input: &str) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> { Ok(Vec::new()) })().map_err(|err| {
            match err.downcast::<JoseError>() {
                Ok(err) => err,
                Err(err) => JoseError::InvalidJwtFormat(err),
            }
        })
    }
}

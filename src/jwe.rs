pub mod alg_rsaes;
pub mod alg_aes;
pub mod alg_dir;
pub mod alg_ecdh_es;
pub mod alg_ecdh_es_aes;
pub mod alg_aes_gcm;
pub mod alg_pbes2_aes;
pub mod enc_aes_cbc_hmac;
pub mod enc_aes_gcm;

use anyhow::bail;
use serde_json::{Map, Value};

use crate::error::JoseError;
use crate::jwk::Jwk;

pub trait JweAlgorithm {
    /// Return the "alg" (algorithm) header parameter value of JWE.
    fn name(&self) -> &str;

    /// Return the encrypter from a JWK private key.
    ///
    /// # Arguments
    /// * `jwk` - a JWK private key.
    /// * `encryption` - a JWE encryption algorithm.
    fn encrypter_from_jwk(&self, jwk: &Jwk, encryption: &dyn JweEncryption) -> Result<Box<dyn JweEncrypter>, JoseError>;

    /// Return the decrypter from a JWK key.
    ///
    /// # Arguments
    /// * `jwk` - a JWK key.
    /// * `encryption` - a JWE encryption algorithm.
    fn decrypter_from_jwk(&self, jwk: &Jwk, encryption: &dyn JweEncryption) -> Result<Box<dyn JweDecrypter>, JoseError>;
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

    fn serialize_compact(
        &self,
        header: &Map<String, Value>,
        payload: &[u8],
    ) -> Result<String, JoseError> {
        (|| -> anyhow::Result<String> {
            let mut b64 = true;
            if let Some(Value::Bool(false)) = header.get("b64") {
                if let Some(Value::Array(vals)) = header.get("crit") {
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

    fn deserialize_compact(
        &self,
        header: &Map<String, Value>,
        input: &str,
    ) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            Ok(Vec::new())
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err),
        })
    }
}

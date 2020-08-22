use anyhow::bail;
use serde_json::Value;

use crate::jose::JoseError;
use crate::jwe::{JweAlgorithm, JweDecrypter, JweEncrypter};
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
    pub fn encrypter_from_jwk(&self, jwk: &Jwk) -> Result<Pbes2HmacAesJweEncrypter, JoseError> {
        (|| -> anyhow::Result<Pbes2HmacAesJweEncrypter> {
            match jwk.key_type() {
                val if val == "oct" => {}
                val => bail!("A parameter kty must be oct: {}", val),
            }
            match jwk.key_use() {
                Some(val) if val == "enc" => {}
                None => {}
                Some(val) => bail!("A parameter use must be enc: {}", val),
            }
            match jwk.key_operations() {
                Some(vals) if vals.iter().any(|e| e == "encrypt") => {}
                None => {}
                _ => bail!("A parameter key_ops must contains encrypt."),
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }
            let k = match jwk.parameter("k") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(val) => bail!("A parameter k must be string type but {:?}", val),
                None => bail!("A parameter k is required."),
            };

            Ok(Pbes2HmacAesJweEncrypter {
                algorithm: self.clone(),
                private_key: k,
                key_id: jwk.key_id().map(|val| val.to_string()),
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn decrypter_from_jwk(&self, jwk: &Jwk) -> Result<Pbes2HmacAesJweDecrypter, JoseError> {
        (|| -> anyhow::Result<Pbes2HmacAesJweDecrypter> {
            match jwk.key_type() {
                val if val == "oct" => {}
                val => bail!("A parameter kty must be oct: {}", val),
            }
            match jwk.key_use() {
                Some(val) if val == "enc" => {}
                None => {}
                Some(val) => bail!("A parameter use must be enc: {}", val),
            }
            match jwk.key_operations() {
                Some(vals) if vals.iter().any(|e| e == "decrypt") => {}
                None => {}
                _ => bail!("A parameter key_ops must contains decrypt."),
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }

            let k = match jwk.parameter("k") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(val) => bail!("A parameter k must be string type but {:?}", val),
                None => bail!("A parameter k is required."),
            };

            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(Pbes2HmacAesJweDecrypter {
                algorithm: self.clone(),
                private_key: k,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
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
        
    fn box_clone(&self) -> Box<dyn JweAlgorithm> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Clone)]
pub struct Pbes2HmacAesJweEncrypter {
    algorithm: Pbes2HmacAesJweAlgorithm,
    private_key: Vec<u8>,
    key_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Pbes2HmacAesJweDecrypter {
    algorithm: Pbes2HmacAesJweAlgorithm,
    private_key: Vec<u8>,
    key_id: Option<String>,
}

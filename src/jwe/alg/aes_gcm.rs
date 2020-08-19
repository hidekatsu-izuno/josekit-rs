use anyhow::bail;
use serde_json::Value;

use crate::jose::JoseError;
use crate::jwe::{JweAlgorithm, JweDecrypter, JweEncrypter};
use crate::jwk::Jwk;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AesGcmJweAlgorithm {
    /// Key wrapping with AES GCM using 128-bit key
    A128GcmKw,
    /// Key wrapping with AES GCM using 192-bit key
    A192GcmKw,
    /// Key wrapping with AES GCM using 256-bit key
    A256GcmKw,
}

impl AesGcmJweAlgorithm {
    pub fn encrypter_from_jwk(&self, jwk: &Jwk) -> Result<AesGcmJweEncrypter, JoseError> {
        (|| -> anyhow::Result<AesGcmJweEncrypter> {
            match jwk.key_type() {
                val if val == self.key_type() => {}
                val => bail!("A parameter kty must be {}: {}", self.key_type(), val),
            }
            match jwk.key_use() {
                Some(val) if val == "enc" => {}
                None => {}
                Some(val) => bail!("A parameter use must be enc: {}", val),
            }
            match jwk.key_operations() {
                Some(vals) => {
                    if !vals.iter().any(|e| e == "encrypt")
                        || !vals.iter().any(|e| e == "wrapKey") {
                        bail!("A parameter key_ops must contains encrypt and wrapKey.");
                    }
                },
                None => {},
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

            Ok(AesGcmJweEncrypter {
                algorithm: self.clone(),
                private_key: k,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn decrypter_from_jwk(&self, jwk: &Jwk) -> Result<AesGcmJweDecrypter, JoseError> {
        (|| -> anyhow::Result<AesGcmJweDecrypter> {
            match jwk.key_type() {
                val if val == self.key_type() => {}
                val => bail!("A parameter kty must be {}: {}", self.key_type(), val),
            }
            match jwk.key_use() {
                Some(val) if val == "enc" => {}
                None => {}
                Some(val) => bail!("A parameter use must be enc: {}", val),
            }
            match jwk.key_operations() {
                Some(vals) => {
                    if !vals.iter().any(|e| e == "decrypt")
                        || !vals.iter().any(|e| e == "unwrapKey") {
                        bail!("A parameter key_ops must contains decrypt and unwrapKey.");
                    }
                },
                None => {},
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

            Ok(AesGcmJweDecrypter {
                algorithm: self.clone(),
                private_key: k,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }
}

impl JweAlgorithm for AesGcmJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::A128GcmKw => "A128GCMKW",
            Self::A192GcmKw => "A192GCMKW",
            Self::A256GcmKw => "A256GCMKW",
        }
    }

    fn key_type(&self) -> &str {
        "oct"
    }
}

#[derive(Debug, Clone)]
pub struct AesGcmJweEncrypter {
    algorithm: AesGcmJweAlgorithm,
    private_key: Vec<u8>,
    key_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AesGcmJweDecrypter {
    algorithm: AesGcmJweAlgorithm,
    private_key: Vec<u8>,
    key_id: Option<String>,
}

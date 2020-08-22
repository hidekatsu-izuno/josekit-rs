use std::borrow::Cow;
use anyhow::bail;
use serde_json::Value;

use crate::jose::JoseError;
use crate::jwe::{JweHeader, JweAlgorithm, JweDecrypter, JweEncrypter};
use crate::jwk::Jwk;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AesJweAlgorithm {
    /// AES Key Wrap with default initial value using 128-bit key
    A128Kw,
    /// AES Key Wrap with default initial value using 192-bit key
    A192Kw,
    /// AES Key Wrap with default initial value using 256-bit key
    A256Kw,
}

impl AesJweAlgorithm {
    pub fn encrypter_from_jwk(&self, jwk: &Jwk) -> Result<AesJweEncrypter, JoseError> {
        (|| -> anyhow::Result<AesJweEncrypter> {
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

            Ok(AesJweEncrypter {
                algorithm: self.clone(),
                private_key: k,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn decrypter_from_jwk(&self, jwk: &Jwk) -> Result<AesJweDecrypter, JoseError> {
        (|| -> anyhow::Result<AesJweDecrypter> {
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

            Ok(AesJweDecrypter {
                algorithm: self.clone(),
                private_key: k,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }
}

impl JweAlgorithm for AesJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::A128Kw => "A128KW",
            Self::A192Kw => "A192KW",
            Self::A256Kw => "A256KW",
        }
    }
    
    fn box_clone(&self) -> Box<dyn JweAlgorithm> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Clone)]
pub struct AesJweEncrypter {
    algorithm: AesJweAlgorithm,
    private_key: Vec<u8>,
    key_id: Option<String>,
}

impl JweEncrypter for AesJweEncrypter {
    fn algorithm(&self) -> &dyn JweAlgorithm {
        &self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn set_key_id(&mut self, key_id: &str) {
        self.key_id = Some(key_id.to_string());
    }

    fn remove_key_id(&mut self) {
        self.key_id = None;
    }

    fn encrypt(&self, header: &mut JweHeader) -> Result<(Cow<[u8]>, Option<Vec<u8>>), JoseError> {
        todo!();
    }
    
    fn box_clone(&self) -> Box<dyn JweEncrypter> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Clone)]
pub struct AesJweDecrypter {
    algorithm: AesJweAlgorithm,
    private_key: Vec<u8>,
    key_id: Option<String>,
}

impl JweDecrypter for AesJweDecrypter {
    fn algorithm(&self) -> &dyn JweAlgorithm {
        &self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn set_key_id(&mut self, key_id: &str) {
        self.key_id = Some(key_id.to_string());
    }

    fn remove_key_id(&mut self) {
        self.key_id = None;
    }

    fn decrypt(&self, header: &JweHeader, encrypted_key: &[u8]) -> Result<Cow<[u8]>, JoseError> {
        todo!();
    }
        
    fn box_clone(&self) -> Box<dyn JweDecrypter> {
        Box::new(self.clone())
    }
}

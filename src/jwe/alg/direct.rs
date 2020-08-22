use std::borrow::Cow;

use anyhow::bail;
use serde_json::Value;

use crate::jose::JoseError;
use crate::jwe::{JweHeader, JweAlgorithm, JweDecrypter, JweEncrypter};
use crate::jwk::Jwk;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum DirectJweAlgorithm {
    /// Direct use of a shared symmetric key as the CEK
    Dir,
}

impl DirectJweAlgorithm {
    pub fn encrypter_from_slice(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<DirectJweEncrypter, JoseError> {
        let content_encryption_key = input.as_ref();

        Ok(DirectJweEncrypter {
            algorithm: self.clone(),
            content_encryption_key: content_encryption_key.to_vec(),
            key_id: None,
        })
    }

    pub fn encrypter_from_jwk(&self, jwk: &Jwk) -> Result<DirectJweEncrypter, JoseError> {
        (|| -> anyhow::Result<DirectJweEncrypter> {
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
            
            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(DirectJweEncrypter {
                algorithm: self.clone(),
                content_encryption_key: k,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn decrypter_from_slice(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<DirectJweDecrypter, JoseError> {
        let content_encryption_key = input.as_ref();

        Ok(DirectJweDecrypter {
            algorithm: self.clone(),
            content_encryption_key: content_encryption_key.to_vec(),
            key_id: None,
        })
    }

    pub fn decrypter_from_jwk(&self, jwk: &Jwk) -> Result<DirectJweDecrypter, JoseError> {
        (|| -> anyhow::Result<DirectJweDecrypter> {
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

            Ok(DirectJweDecrypter {
                algorithm: self.clone(),
                content_encryption_key: k,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }
}

impl JweAlgorithm for DirectJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::Dir => "dir",
        }
    }
        
    fn box_clone(&self) -> Box<dyn JweAlgorithm> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Clone)]
pub struct DirectJweEncrypter {
    algorithm: DirectJweAlgorithm,
    content_encryption_key: Vec<u8>,
    key_id: Option<String>,
}

impl JweEncrypter for DirectJweEncrypter {
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
        header.set_algorithm(self.algorithm.name());
        Ok((Cow::Borrowed(&self.content_encryption_key), None))
    }
    
    fn box_clone(&self) -> Box<dyn JweEncrypter> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Clone)]
pub struct DirectJweDecrypter {
    algorithm: DirectJweAlgorithm,
    key_id: Option<String>,
    content_encryption_key: Vec<u8>,
}

impl JweDecrypter for DirectJweDecrypter {
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

    fn decrypt(&self, _header: &JweHeader, encrypted_key: &[u8]) -> Result<Cow<[u8]>, JoseError> {
        (|| -> anyhow::Result<()> {
            if encrypted_key.len() != 0 {
                bail!("The encrypted_key must be empty.");
            }

            Ok(())
        })()
        .map_err(|err| JoseError::InvalidJweFormat(err))?;

        Ok(Cow::Borrowed(&self.content_encryption_key))
    }
    
    fn box_clone(&self) -> Box<dyn JweDecrypter> {
        Box::new(self.clone())
    }
}

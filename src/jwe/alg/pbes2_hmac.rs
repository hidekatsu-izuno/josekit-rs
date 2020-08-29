use std::borrow::Cow;
use std::convert::TryFrom;

use anyhow::bail;
use openssl::aes::{self, AesKey};
use openssl::hash::MessageDigest;
use openssl::pkcs5;
use openssl::rand;
use serde_json::Value;

use crate::jose::{JoseError, JoseHeader};
use crate::jwe::{JweAlgorithm, JweDecrypter, JweEncrypter, JweHeader};
use crate::jwk::Jwk;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Pbes2HmacJweAlgorithm {
    /// PBES2 with HMAC SHA-256 and "A128KW" wrapping
    Pbes2HS256A128Kw,
    /// PBES2 with HMAC SHA-384 and "A192KW" wrapping
    Pbes2HS384A192Kw,
    /// PBES2 with HMAC SHA-512 and "A256KW" wrapping
    Pbes2HS512A256Kw,
}

impl Pbes2HmacJweAlgorithm {
    pub fn encrypter_from_jwk(&self, jwk: &Jwk) -> Result<Pbes2HmacJweEncrypter, JoseError> {
        (|| -> anyhow::Result<Pbes2HmacJweEncrypter> {
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

            Ok(Pbes2HmacJweEncrypter {
                algorithm: self.clone(),
                private_key: k,
                key_id: jwk.key_id().map(|val| val.to_string()),
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn decrypter_from_jwk(&self, jwk: &Jwk) -> Result<Pbes2HmacJweDecrypter, JoseError> {
        (|| -> anyhow::Result<Pbes2HmacJweDecrypter> {
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

            Ok(Pbes2HmacJweDecrypter {
                algorithm: self.clone(),
                private_key: k,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn digest(&self) -> MessageDigest {
        match self {
            Self::Pbes2HS256A128Kw => MessageDigest::sha256(),
            Self::Pbes2HS384A192Kw => MessageDigest::sha384(),
            Self::Pbes2HS512A256Kw => MessageDigest::sha512(),
        }
    }
}

impl JweAlgorithm for Pbes2HmacJweAlgorithm {
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
pub struct Pbes2HmacJweEncrypter {
    algorithm: Pbes2HmacJweAlgorithm,
    private_key: Vec<u8>,
    key_id: Option<String>,
}

impl JweEncrypter for Pbes2HmacJweEncrypter {
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

    fn encrypt(
        &self,
        header: &mut JweHeader,
        key_len: usize,
    ) -> Result<(Cow<[u8]>, Option<Vec<u8>>), JoseError> {
        (|| -> anyhow::Result<(Cow<[u8]>, Option<Vec<u8>>)> {
            let p2s = match header.claim("p2s") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("The p2s header claim must be string."),
                None => {
                    let mut p2s = vec![0, 8];
                    rand::rand_bytes(&mut p2s)?;
                    p2s
                }
            };
            let p2c = match header.claim("p2c") {
                Some(Value::Number(val)) => match val.as_u64() {
                    Some(val) => usize::try_from(val)?,
                    None => bail!("Overflow u64 value: {}", val),
                },
                Some(_) => bail!("The apv header claim must be string."),
                None => 1000,
            };

            let md = self.algorithm.digest();

            let mut derived_key = vec![0; key_len];
            pkcs5::pbkdf2_hmac(&self.private_key, &p2s, p2c, md, &mut derived_key)?;

            let mut key = vec![0; key_len];
            rand::rand_bytes(&mut key)?;

            let aes = match AesKey::new_encrypt(&derived_key) {
                Ok(val) => val,
                Err(err) => bail!("{:?}", err),
            };

            let mut encrypted_key = vec![0; key_len + 8];
            let len = match aes::wrap_key(&aes, None, &mut encrypted_key, &key) {
                Ok(val) => val,
                Err(err) => bail!("{:?}", err),
            };
            if len < encrypted_key.len() {
                encrypted_key.truncate(len);
            }

            header.set_algorithm(self.algorithm.name());
            Ok((Cow::Owned(key), Some(encrypted_key)))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn box_clone(&self) -> Box<dyn JweEncrypter> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Clone)]
pub struct Pbes2HmacJweDecrypter {
    algorithm: Pbes2HmacJweAlgorithm,
    private_key: Vec<u8>,
    key_id: Option<String>,
}

impl JweDecrypter for Pbes2HmacJweDecrypter {
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

    fn decrypt(
        &self,
        header: &JweHeader,
        encrypted_key: Option<&[u8]>,
        key_len: usize,
    ) -> Result<Cow<[u8]>, JoseError> {
        (|| -> anyhow::Result<Cow<[u8]>> {
            let encrypted_key = match encrypted_key {
                Some(val) => val,
                None => bail!("A encrypted_key value is required."),
            };

            let p2s = match header.claim("p2s") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("The p2s header claim must be string."),
                None => bail!("The p2s header claim is required."),
            };
            let p2c = match header.claim("p2c") {
                Some(Value::Number(val)) => match val.as_u64() {
                    Some(val) => usize::try_from(val)?,
                    None => bail!("Overflow u64 value: {}", val),
                },
                Some(_) => bail!("The p2s header claim must be string."),
                None => bail!("The p2c header claim is required."),
            };

            let md = self.algorithm.digest();

            let mut derived_key = vec![0; key_len];
            pkcs5::pbkdf2_hmac(&self.private_key, &p2s, p2c, md, &mut derived_key)?;

            let aes = match AesKey::new_encrypt(&derived_key) {
                Ok(val) => val,
                Err(err) => bail!("{:?}", err),
            };

            let mut key = vec![0; key_len + 8];
            let len = match aes::unwrap_key(&aes, None, &mut key, &encrypted_key) {
                Ok(val) => val,
                Err(err) => bail!("{:?}", err),
            };
            if len < key.len() {
                key.truncate(len);
            }

            Ok(Cow::Owned(key))
        })()
        .map_err(|err| JoseError::InvalidJweFormat(err))
    }

    fn box_clone(&self) -> Box<dyn JweDecrypter> {
        Box::new(self.clone())
    }
}

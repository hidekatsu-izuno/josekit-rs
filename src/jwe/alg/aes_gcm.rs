use std::borrow::Cow;

use anyhow::bail;
use serde_json::Value;
use openssl::rand;
use openssl::symm::{self, Cipher};

use crate::jose::{JoseHeader, JoseError};
use crate::jwe::{JweHeader, JweAlgorithm, JweDecrypter, JweEncrypter};
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
            
            if k.len() != self.key_len() {
                bail!("The key size must be {}: {}", self.key_len(), k.len());
            }

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
            
            if k.len() != self.key_len() {
                bail!("The key size must be {}: {}", self.key_len(), k.len());
            }

            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(AesGcmJweDecrypter {
                algorithm: self.clone(),
                private_key: k,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }
    
    fn key_len(&self) -> usize {
        match self {
            Self::A128GcmKw => 16,
            Self::A192GcmKw => 24,
            Self::A256GcmKw => 32,
        }
    }

    fn cipher(&self) -> Cipher {
        match self {
            Self::A128GcmKw => Cipher::aes_128_gcm(),
            Self::A192GcmKw => Cipher::aes_192_gcm(),
            Self::A256GcmKw => Cipher::aes_256_gcm(),
        }
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
        
    fn box_clone(&self) -> Box<dyn JweAlgorithm> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Clone)]
pub struct AesGcmJweEncrypter {
    algorithm: AesGcmJweAlgorithm,
    private_key: Vec<u8>,
    key_id: Option<String>,
}

impl JweEncrypter for AesGcmJweEncrypter {
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

    fn encrypt(&self, header: &mut JweHeader, key_len: usize) -> Result<(Cow<[u8]>, Option<Vec<u8>>), JoseError> {
        (|| -> anyhow::Result<(Cow<[u8]>, Option<Vec<u8>>)> {
            let mut key = vec![0; key_len];
            rand::rand_bytes(&mut key)?;

            let mut iv = vec![0; 32];
            rand::rand_bytes(&mut iv)?;

            let cipher = self.algorithm.cipher();
            let mut tag = [0; 16];
            let encrypted_key = symm::encrypt_aead(cipher, &self.private_key, Some(&iv), b"", &key, &mut tag)?;

            header.set_algorithm(self.algorithm.name());

            let iv = base64::encode_config(&iv, base64::URL_SAFE_NO_PAD);
            header.set_claim("iv", Some(Value::String(iv)))?;

            let tag = base64::encode_config(&tag, base64::URL_SAFE_NO_PAD);            
            header.set_claim("tag", Some(Value::String(tag)))?;

            Ok((Cow::Owned(key), Some(encrypted_key)))
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidKeyFormat(err),
        })
    }
    
    fn box_clone(&self) -> Box<dyn JweEncrypter> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Clone)]
pub struct AesGcmJweDecrypter {
    algorithm: AesGcmJweAlgorithm,
    private_key: Vec<u8>,
    key_id: Option<String>,
}

impl JweDecrypter for AesGcmJweDecrypter {
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

    fn decrypt(&self, header: &JweHeader, encrypted_key: &[u8], key_len: usize) -> Result<Cow<[u8]>, JoseError> {
        (|| -> anyhow::Result<Cow<[u8]>> {
            let iv = match header.claim("iv") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("The iv header claim must be string."),
                None => bail!("The iv header claim is required."),
            };

            let tag = match header.claim("tag") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("The tag header claim must be string."),
                None => bail!("The tag header claim is required."),
            };

            let cipher = self.algorithm.cipher();
            let key = symm::decrypt_aead(cipher, &self.private_key, Some(&iv), b"", encrypted_key, &tag)?;
            if key.len() != key_len {
                bail!("The key size is expected to be {}: {}", key_len, key.len());
            }
            
            Ok(Cow::Owned(key))
        })()
        .map_err(|err| JoseError::InvalidJweFormat(err))
    }
        
    fn box_clone(&self) -> Box<dyn JweDecrypter> {
        Box::new(self.clone())
    }
}

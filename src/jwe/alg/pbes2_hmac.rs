use std::borrow::Cow;
use std::convert::TryFrom;
use std::fmt::Display;
use std::ops::Deref;

use anyhow::bail;
use openssl::aes::{self, AesKey};
use openssl::hash::MessageDigest;
use openssl::pkcs5;
use openssl::rand;
use serde_json::{Number, Value};

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
    pub fn encrypter_from_slice(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<Pbes2HmacJweEncrypter, JoseError> {
        (|| -> anyhow::Result<Pbes2HmacJweEncrypter> {
            let private_key = input.as_ref().to_vec();

            if private_key.len() == 0 {
                bail!("The key size must not be empty.");
            }

            Ok(Pbes2HmacJweEncrypter {
                algorithm: self.clone(),
                private_key,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

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
            if !jwk.is_for_key_operation("deriveKey") {
                bail!("A parameter key_ops must contains deriveKey.");
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

            if k.len() == 0 {
                bail!("The key size must not be empty.");
            }

            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(Pbes2HmacJweEncrypter {
                algorithm: self.clone(),
                private_key: k,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn decrypter_from_slice(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<Pbes2HmacJweDecrypter, JoseError> {
        (|| -> anyhow::Result<Pbes2HmacJweDecrypter> {
            let private_key = input.as_ref().to_vec();

            if private_key.len() == 0 {
                bail!("The key size must not be empty.");
            }

            Ok(Pbes2HmacJweDecrypter {
                algorithm: self.clone(),
                private_key,
                key_id: None,
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
            if !jwk.is_for_key_operation("deriveKey") {
                bail!("A parameter key_ops must contains deriveKey.");
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

            if k.len() == 0 {
                bail!("The key size must not be empty.");
            }

            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(Pbes2HmacJweDecrypter {
                algorithm: self.clone(),
                private_key: k,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn md(&self) -> MessageDigest {
        match self {
            Self::Pbes2HS256A128Kw => MessageDigest::sha256(),
            Self::Pbes2HS384A192Kw => MessageDigest::sha384(),
            Self::Pbes2HS512A256Kw => MessageDigest::sha512(),
        }
    }

    fn derived_key_len(&self) -> usize {
        match self {
            Self::Pbes2HS256A128Kw => 16,
            Self::Pbes2HS384A192Kw => 24,
            Self::Pbes2HS512A256Kw => 32,
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

impl Display for Pbes2HmacJweAlgorithm {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for Pbes2HmacJweAlgorithm {
    type Target = dyn JweAlgorithm;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct Pbes2HmacJweEncrypter {
    algorithm: Pbes2HmacJweAlgorithm,
    private_key: Vec<u8>,
    key_id: Option<String>,
}

impl Pbes2HmacJweEncrypter {
    pub fn set_key_id(&mut self, key_id: Option<impl Into<String>>) {
        match key_id {
            Some(val) => {
                self.key_id = Some(val.into());
            }
            None => {
                self.key_id = None;
            }
        }
    }
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
                    let p2s_b64 = base64::encode_config(&p2s, base64::URL_SAFE_NO_PAD);
                    header.set_claim("p2s", Some(Value::String(p2s_b64)))?;
                    p2s
                }
            };
            let p2c = match header.claim("p2c") {
                Some(Value::Number(val)) => match val.as_u64() {
                    Some(val) => usize::try_from(val)?,
                    None => bail!("Overflow u64 value: {}", val),
                },
                Some(_) => bail!("The apv header claim must be string."),
                None => {
                    let p2c = 1000;
                    header.set_claim("p2c", Some(Value::Number(Number::from(p2c))))?;
                    p2c
                }
            };

            let md = self.algorithm.md();
            let mut derived_key = vec![0; self.algorithm.derived_key_len()];
            pkcs5::pbkdf2_hmac(&self.private_key, &p2s, p2c, md, &mut derived_key)?;

            let aes = match AesKey::new_encrypt(&derived_key) {
                Ok(val) => val,
                Err(_) => bail!("Failed to set encrypt key."),
            };

            let mut key = vec![0; key_len];
            rand::rand_bytes(&mut key)?;

            let mut encrypted_key = vec![0; key_len + 8];
            let len = match aes::wrap_key(&aes, None, &mut encrypted_key, &key) {
                Ok(val) => val,
                Err(_) => bail!("Failed to wrap key."),
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

impl Deref for Pbes2HmacJweEncrypter {
    type Target = dyn JweEncrypter;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct Pbes2HmacJweDecrypter {
    algorithm: Pbes2HmacJweAlgorithm,
    private_key: Vec<u8>,
    key_id: Option<String>,
}

impl Pbes2HmacJweDecrypter {
    pub fn set_key_id(&mut self, key_id: Option<impl Into<String>>) {
        match key_id {
            Some(val) => {
                self.key_id = Some(val.into());
            }
            None => {
                self.key_id = None;
            }
        }
    }
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

            let md = self.algorithm.md();
            let mut derived_key = vec![0; self.algorithm.derived_key_len()];
            pkcs5::pbkdf2_hmac(&self.private_key, &p2s, p2c, md, &mut derived_key)?;

            let aes = match AesKey::new_decrypt(&derived_key) {
                Ok(val) => val,
                Err(_) => bail!("Failed to set decrypt key."),
            };

            let mut key = vec![0; key_len];
            let len = match aes::unwrap_key(&aes, None, &mut key, &encrypted_key) {
                Ok(val) => val,
                Err(_) => bail!("Failed to unwrap key."),
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

impl Deref for Pbes2HmacJweDecrypter {
    type Target = dyn JweDecrypter;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use base64;
    use openssl::rand;
    use serde_json::json;

    use super::Pbes2HmacJweAlgorithm;
    use crate::jwe::enc::aes_cbc_hmac::AesCbcHmacJweEncryption;
    use crate::jwe::JweHeader;
    use crate::jwk::Jwk;

    #[test]
    fn encrypt_and_decrypt_pbes2_hmac() -> Result<()> {
        let enc = AesCbcHmacJweEncryption::A128CbcHS256;

        for alg in vec![
            Pbes2HmacJweAlgorithm::Pbes2HS256A128Kw,
            Pbes2HmacJweAlgorithm::Pbes2HS384A192Kw,
            Pbes2HmacJweAlgorithm::Pbes2HS512A256Kw,
        ] {
            let mut header = JweHeader::new();
            header.set_content_encryption(enc.name());

            let jwk = {
                let mut key = vec![0; 25];
                rand::rand_bytes(&mut key)?;
                let key = base64::encode_config(&key, base64::URL_SAFE_NO_PAD);

                let mut jwk = Jwk::new("oct");
                jwk.set_key_use("enc");
                jwk.set_parameter("k", Some(json!(key)))?;
                jwk
            };

            let encrypter = alg.encrypter_from_jwk(&jwk)?;
            let (src_key, encrypted_key) = encrypter.encrypt(&mut header, enc.key_len())?;

            let decrypter = alg.decrypter_from_jwk(&jwk)?;

            let dst_key = decrypter.decrypt(&header, encrypted_key.as_deref(), enc.key_len())?;

            assert_eq!(&src_key, &dst_key);
        }

        Ok(())
    }
}

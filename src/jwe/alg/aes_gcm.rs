use std::borrow::Cow;
use std::ops::Deref;

use anyhow::bail;
use openssl::rand;
use openssl::symm::{self, Cipher};
use serde_json::Value;

use crate::jose::{JoseError, JoseHeader};
use crate::jwe::{JweAlgorithm, JweDecrypter, JweEncrypter, JweHeader};
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
            if !jwk.is_for_key_operation("encrypt") {
                bail!("A parameter key_ops must contains encrypt.");
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
            if !jwk.is_for_key_operation("decrypt") {
                bail!("A parameter key_ops must contains decrypt.");
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

impl Deref for AesGcmJweAlgorithm {
    type Target = dyn JweAlgorithm;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct AesGcmJweEncrypter {
    algorithm: AesGcmJweAlgorithm,
    private_key: Vec<u8>,
    key_id: Option<String>,
}

impl AesGcmJweEncrypter {
    pub fn set_key_id(&mut self, key_id: Option<impl Into<String>>) {
        match key_id {
            Some(val) => {
                self.key_id = Some(val.into());
            },
            None => {
                self.key_id = None;
            }
        }
    }
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

    fn encrypt(
        &self,
        header: &mut JweHeader,
        key_len: usize,
    ) -> Result<(Cow<[u8]>, Option<Vec<u8>>), JoseError> {
        (|| -> anyhow::Result<(Cow<[u8]>, Option<Vec<u8>>)> {
            let mut key = vec![0; key_len];
            rand::rand_bytes(&mut key)?;

            let mut iv = vec![0; 32];
            rand::rand_bytes(&mut iv)?;

            let cipher = self.algorithm.cipher();
            let mut tag = [0; 16];
            let encrypted_key =
                symm::encrypt_aead(cipher, &self.private_key, Some(&iv), b"", &key, &mut tag)?;

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

impl Deref for AesGcmJweEncrypter {
    type Target = dyn JweEncrypter;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct AesGcmJweDecrypter {
    algorithm: AesGcmJweAlgorithm,
    private_key: Vec<u8>,
    key_id: Option<String>,
}

impl AesGcmJweDecrypter {
    pub fn set_key_id(&mut self, key_id: Option<impl Into<String>>) {
        match key_id {
            Some(val) => {
                self.key_id = Some(val.into());
            },
            None => {
                self.key_id = None;
            }
        }
    }
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

    fn decrypt(
        &self,
        header: &JweHeader,
        encrypted_key: Option<&[u8]>,
        key_len: usize,
    ) -> Result<Cow<[u8]>, JoseError> {
        (|| -> anyhow::Result<Cow<[u8]>> {
            let encrypted_key = match encrypted_key {
                Some(val) => val,
                None => bail!("A encrypted_key is required."),
            };

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
            let key = symm::decrypt_aead(
                cipher,
                &self.private_key,
                Some(&iv),
                b"",
                encrypted_key,
                &tag,
            )?;
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

impl Deref for AesGcmJweDecrypter {
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

    use super::AesGcmJweAlgorithm;
    use crate::jwe::JweHeader;
    use crate::jwe::enc::aes_cbc_hmac::AesCbcHmacJweEncryption;
    use crate::jwk::Jwk;

    #[test]
    fn encrypt_and_decrypt_aes_gcm() -> Result<()> {
        let enc = AesCbcHmacJweEncryption::A128CbcHS256;

        for alg in vec![
            AesGcmJweAlgorithm::A128GcmKw,
            AesGcmJweAlgorithm::A192GcmKw,
            AesGcmJweAlgorithm::A256GcmKw,
        ] {
            let mut header = JweHeader::new();
            header.set_content_encryption(enc.name());

            let jwk = {
                let mut key = vec![0; alg.key_len()];
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

use std::borrow::Cow;
use std::fmt::Display;
use std::ops::Deref;

#[cfg(any(feature = "aes-kw-rustcrypto", feature = "x448-goldilocks-plus"))]
use aes_kw::{KeyInit, KwAes192};
#[cfg(all(
    any(feature = "aes-kw-rustcrypto", feature = "x448-goldilocks-plus"),
    not(feature = "aws-lc-rs")
))]
use aes_kw::{KwAes128, KwAes256};
use anyhow::{bail, Context};
#[cfg(feature = "aws-lc-rs")]
use aws_lc_rs::key_wrap::KeyWrap;
#[cfg(not(any(feature = "aes-kw-rustcrypto", feature = "x448-goldilocks-plus")))]
use openssl::aes::{self, AesKey};

use crate::jwe::{JweAlgorithm, JweContentEncryption, JweDecrypter, JweEncrypter, JweHeader};
use crate::jwk::Jwk;
use crate::{util, JoseError, Value};

const IV_LEN: usize = 8;

pub(crate) fn wrap_key(kek: &[u8], key: &[u8]) -> anyhow::Result<Vec<u8>> {
    if key.is_empty() {
        bail!("The key to wrap must not be empty.");
    }

    let mut wrapped = vec![0; key.len() + IV_LEN];
    #[cfg(feature = "aws-lc-rs")]
    if matches!(kek.len(), 16 | 32) {
        crate::aws_lc::key_wrap_key(kek)?.wrap(key, &mut wrapped)?;
        return Ok(wrapped);
    }
    #[cfg(any(feature = "aes-kw-rustcrypto", feature = "x448-goldilocks-plus"))]
    match kek.len() {
        #[cfg(not(feature = "aws-lc-rs"))]
        16 => KwAes128::new_from_slice(kek)?.wrap_key(key, &mut wrapped)?,
        24 => KwAes192::new_from_slice(kek)?.wrap_key(key, &mut wrapped)?,
        #[cfg(not(feature = "aws-lc-rs"))]
        32 => KwAes256::new_from_slice(kek)?.wrap_key(key, &mut wrapped)?,
        _ => bail!("Invalid AES Key Wrap key size."),
    };
    #[cfg(not(any(feature = "aes-kw-rustcrypto", feature = "x448-goldilocks-plus")))]
    {
        let aes =
            AesKey::new_encrypt(kek).map_err(|_| anyhow::anyhow!("Failed to set encrypt key."))?;
        let len = aes::wrap_key(&aes, None, &mut wrapped, key)
            .map_err(|_| anyhow::anyhow!("Failed to wrap key."))?;
        wrapped.truncate(len);
    }
    Ok(wrapped)
}

pub(crate) fn unwrap_key(kek: &[u8], wrapped: &[u8]) -> anyhow::Result<Vec<u8>> {
    let key_len = wrapped
        .len()
        .checked_sub(IV_LEN)
        .filter(|&len| len != 0)
        .context("The wrapped key is too short.")?;
    let mut key = vec![0; key_len];
    #[cfg(feature = "aws-lc-rs")]
    if matches!(kek.len(), 16 | 32) {
        crate::aws_lc::key_wrap_key(kek)?.unwrap(wrapped, &mut key)?;
        return Ok(key);
    }
    #[cfg(any(feature = "aes-kw-rustcrypto", feature = "x448-goldilocks-plus"))]
    match kek.len() {
        #[cfg(not(feature = "aws-lc-rs"))]
        16 => KwAes128::new_from_slice(kek)?.unwrap_key(wrapped, &mut key)?,
        24 => KwAes192::new_from_slice(kek)?.unwrap_key(wrapped, &mut key)?,
        #[cfg(not(feature = "aws-lc-rs"))]
        32 => KwAes256::new_from_slice(kek)?.unwrap_key(wrapped, &mut key)?,
        _ => bail!("Invalid AES Key Wrap key size."),
    };
    #[cfg(not(any(feature = "aes-kw-rustcrypto", feature = "x448-goldilocks-plus")))]
    {
        let aes =
            AesKey::new_decrypt(kek).map_err(|_| anyhow::anyhow!("Failed to set decrypt key."))?;
        let len = aes::unwrap_key(&aes, None, &mut key, wrapped)
            .map_err(|_| anyhow::anyhow!("Failed to unwrap key."))?;
        key.truncate(len);
    }
    Ok(key)
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AeskwJweAlgorithm {
    /// AES Key Wrap with default initial value using 128-bit key
    A128kw,
    /// AES Key Wrap with default initial value using 192-bit key
    A192kw,
    /// AES Key Wrap with default initial value using 256-bit key
    A256kw,
}

impl AeskwJweAlgorithm {
    pub fn encrypter_from_bytes(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<AeskwJweEncrypter, JoseError> {
        (|| -> anyhow::Result<AeskwJweEncrypter> {
            let private_key = input.as_ref().to_vec();

            if private_key.len() != self.key_len() {
                bail!(
                    "The key size must be {}: {}",
                    self.key_len(),
                    private_key.len()
                );
            }

            Ok(AeskwJweEncrypter {
                algorithm: self.clone(),
                private_key,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn encrypter_from_jwk(&self, jwk: &Jwk) -> Result<AeskwJweEncrypter, JoseError> {
        (|| -> anyhow::Result<AeskwJweEncrypter> {
            match jwk.key_type() {
                val if val == "oct" => {}
                val => bail!("A parameter kty must be oct: {}", val),
            }
            match jwk.key_use() {
                Some(val) if val == "enc" => {}
                None => {}
                Some(val) => bail!("A parameter use must be enc: {}", val),
            }
            if !jwk.is_for_key_operation("wrapKey") {
                bail!("A parameter key_ops must contains wrapKey.");
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }
            let k = match jwk.parameter("k") {
                Some(Value::String(val)) => util::decode_base64_urlsafe_no_pad(val)?,
                Some(val) => bail!("A parameter k must be string type but {:?}", val),
                None => bail!("A parameter k is required."),
            };

            if k.len() != self.key_len() {
                bail!("The key size must be {}: {}", self.key_len(), k.len());
            }

            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(AeskwJweEncrypter {
                algorithm: self.clone(),
                private_key: k,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn decrypter_from_bytes(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<AeskwJweDecrypter, JoseError> {
        (|| -> anyhow::Result<AeskwJweDecrypter> {
            let private_key = input.as_ref().to_vec();

            if private_key.len() != self.key_len() {
                bail!(
                    "The key size must be {}: {}",
                    self.key_len(),
                    private_key.len()
                );
            }

            Ok(AeskwJweDecrypter {
                algorithm: self.clone(),
                private_key,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn decrypter_from_jwk(&self, jwk: &Jwk) -> Result<AeskwJweDecrypter, JoseError> {
        (|| -> anyhow::Result<AeskwJweDecrypter> {
            match jwk.key_type() {
                val if val == "oct" => {}
                val => bail!("A parameter kty must be oct: {}", val),
            }
            match jwk.key_use() {
                Some(val) if val == "enc" => {}
                None => {}
                Some(val) => bail!("A parameter use must be enc: {}", val),
            }
            if !jwk.is_for_key_operation("unwrapKey") {
                bail!("A parameter key_ops must contains unwrapKey.");
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }

            let k = match jwk.parameter("k") {
                Some(Value::String(val)) => util::decode_base64_urlsafe_no_pad(val)?,
                Some(val) => bail!("A parameter k must be string type but {:?}", val),
                None => bail!("A parameter k is required."),
            };

            if k.len() != self.key_len() {
                bail!("The key size must be {}: {}", self.key_len(), k.len());
            }

            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(AeskwJweDecrypter {
                algorithm: self.clone(),
                private_key: k,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn key_len(&self) -> usize {
        match self {
            Self::A128kw => 16,
            Self::A192kw => 24,
            Self::A256kw => 32,
        }
    }
}

impl JweAlgorithm for AeskwJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::A128kw => "A128KW",
            Self::A192kw => "A192KW",
            Self::A256kw => "A256KW",
        }
    }

    fn box_clone(&self) -> Box<dyn JweAlgorithm> {
        Box::new(self.clone())
    }
}

impl Display for AeskwJweAlgorithm {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for AeskwJweAlgorithm {
    type Target = dyn JweAlgorithm;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct AeskwJweEncrypter {
    algorithm: AeskwJweAlgorithm,
    private_key: Vec<u8>,
    key_id: Option<String>,
}

impl AeskwJweEncrypter {
    pub fn set_key_id(&mut self, value: impl Into<String>) {
        self.key_id = Some(value.into());
    }

    pub fn remove_key_id(&mut self) {
        self.key_id = None;
    }
}

impl JweEncrypter for AeskwJweEncrypter {
    fn algorithm(&self) -> &dyn JweAlgorithm {
        &self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn compute_content_encryption_key(
        &self,
        _cencryption: &dyn JweContentEncryption,
        _in_header: &JweHeader,
        _out_header: &mut JweHeader,
    ) -> Result<Option<Cow<'_, [u8]>>, JoseError> {
        Ok(None)
    }

    fn encrypt(
        &self,
        key: &[u8],
        _in_header: &JweHeader,
        _out_header: &mut JweHeader,
    ) -> Result<Option<Vec<u8>>, JoseError> {
        wrap_key(&self.private_key, key)
            .map(Some)
            .map_err(JoseError::InvalidKeyFormat)
    }

    fn box_clone(&self) -> Box<dyn JweEncrypter> {
        Box::new(self.clone())
    }
}

impl Deref for AeskwJweEncrypter {
    type Target = dyn JweEncrypter;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct AeskwJweDecrypter {
    algorithm: AeskwJweAlgorithm,
    private_key: Vec<u8>,
    key_id: Option<String>,
}

impl AeskwJweDecrypter {
    pub fn set_key_id(&mut self, value: impl Into<String>) {
        self.key_id = Some(value.into());
    }

    pub fn remove_key_id(&mut self) {
        self.key_id = None;
    }
}

impl JweDecrypter for AeskwJweDecrypter {
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
        encrypted_key: Option<&[u8]>,
        _cencryption: &dyn JweContentEncryption,
        _header: &JweHeader,
    ) -> Result<Cow<'_, [u8]>, JoseError> {
        (|| -> anyhow::Result<Cow<[u8]>> {
            let encrypted_key = match encrypted_key {
                Some(val) => val,
                None => bail!("A encrypted_key is required."),
            };

            Ok(Cow::Owned(unwrap_key(&self.private_key, encrypted_key)?))
        })()
        .map_err(|err| JoseError::InvalidJweFormat(err))
    }

    fn box_clone(&self) -> Box<dyn JweDecrypter> {
        Box::new(self.clone())
    }
}

impl Deref for AeskwJweDecrypter {
    type Target = dyn JweDecrypter;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use serde_json::json;

    use super::{unwrap_key, wrap_key, AeskwJweAlgorithm};
    use crate::jwe::enc::aescbc_hmac::AescbcHmacJweEncryption;
    use crate::jwe::JweHeader;
    use crate::jwk::Jwk;
    use crate::util;

    #[test]
    fn aes_key_wrap_matches_rfc3394() -> Result<()> {
        // RFC 3394 section 4.1.
        let kek = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let key = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let wrapped = [
            0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47, 0xae, 0xf3, 0x4b, 0xd8, 0xfb, 0x5a,
            0x7b, 0x82, 0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5,
        ];

        assert_eq!(wrap_key(&kek, &key)?, wrapped);
        assert_eq!(unwrap_key(&kek, &wrapped)?, key);
        assert!(unwrap_key(&kek, &wrapped[..7]).is_err());
        Ok(())
    }

    #[test]
    fn encrypt_and_decrypt_aes() -> Result<()> {
        let enc = AescbcHmacJweEncryption::A128cbcHs256;

        for alg in vec![
            AeskwJweAlgorithm::A128kw,
            AeskwJweAlgorithm::A192kw,
            AeskwJweAlgorithm::A256kw,
        ] {
            let mut header = JweHeader::new();
            header.set_content_encryption(enc.name());

            let jwk = {
                let key = util::random_bytes(alg.key_len());
                let key = util::encode_base64_urlsafe_nopad(&key);

                let mut jwk = Jwk::new("oct");
                jwk.set_key_use("enc");
                jwk.set_parameter("k", Some(json!(key)))?;
                jwk
            };

            let encrypter = alg.encrypter_from_jwk(&jwk)?;
            let src_key = util::random_bytes(enc.key_len());
            let mut out_header = header.clone();
            let encrypted_key = encrypter.encrypt(&src_key, &header, &mut out_header)?;

            let decrypter = alg.decrypter_from_jwk(&jwk)?;
            let dst_key = decrypter.decrypt(encrypted_key.as_deref(), &enc, &out_header)?;

            assert_eq!(&src_key as &[u8], &dst_key as &[u8]);
        }

        Ok(())
    }
}

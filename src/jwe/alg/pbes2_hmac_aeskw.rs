use std::borrow::Cow;
use std::convert::TryFrom;
use std::fmt::Display;
use std::ops::Deref;

#[cfg(feature = "rustcrypto")]
use crate::jwe::alg::aeskw::{aes, AesKey};
use crate::jwe::{JweAlgorithm, JweContentEncryption, JweDecrypter, JweEncrypter, JweHeader};
use crate::jwk::Jwk;
use crate::util::{self, HashAlgorithm};
use crate::{JoseError, JoseHeader, Number, Value};
use anyhow::bail;
#[cfg(feature = "openssl")]
use openssl::aes::{self, AesKey};
#[cfg(feature = "openssl")]
use openssl::hash::MessageDigest;
#[cfg(feature = "openssl")]
use openssl::pkcs5;
#[cfg(feature = "rustcrypto")]
use sha1::Sha1;
#[cfg(feature = "rustcrypto")]
use sha2::Digest;
#[cfg(feature = "rustcrypto")]
use sha2::{Sha256, Sha384, Sha512};

#[cfg(feature = "rustcrypto")]
pub enum MessageDigest {
    Sha1(Sha1),
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}
#[cfg(feature = "rustcrypto")]
#[derive(Debug, Clone)]
pub enum Hmac {
    HmacSha1(hmac::Hmac<Sha1>),
    HmacSha256(hmac::Hmac<Sha256>),
    HmacSha384(hmac::Hmac<Sha384>),
    HmacSha512(hmac::Hmac<Sha512>),
}
#[cfg(feature = "rustcrypto")]
impl Hmac {
    pub fn update(&mut self, data: &[u8]) -> Result<(), anyhow::Error> {
        use hmac::digest::Update;
        Ok(match self {
            Hmac::HmacSha1(ref mut hmac) => hmac.update(data),
            Hmac::HmacSha256(ref mut hmac) => hmac.update(data),
            Hmac::HmacSha384(ref mut hmac) => hmac.update(data),
            Hmac::HmacSha512(ref mut hmac) => hmac.update(data),
        })
    }
    pub fn sign_to_vec(self) -> Result<Vec<u8>, anyhow::Error> {
        use hmac::Mac;
        Ok(match self {
            Hmac::HmacSha1(hmac) => hmac.finalize().into_bytes().to_vec(),
            Hmac::HmacSha256(hmac) => hmac.finalize().into_bytes().to_vec(),
            Hmac::HmacSha384(hmac) => hmac.finalize().into_bytes().to_vec(),
            Hmac::HmacSha512(hmac) => hmac.finalize().into_bytes().to_vec(),
        })
    }
}
#[cfg(feature = "rustcrypto")]
impl MessageDigest {
    pub fn sha1() -> Self {
        Self::Sha1(Sha1::new())
    }
    pub fn sha256() -> Self {
        Self::Sha256(Sha256::new())
    }
    pub fn sha384() -> Self {
        Self::Sha384(Sha384::new())
    }
    pub fn sha512() -> Self {
        Self::Sha512(Sha512::new())
    }
    pub fn pbkdf2(&self, password: &[u8], salt: &[u8], rounds: u32, res: &mut [u8]) {
        match self {
            MessageDigest::Sha1(_) => pbkdf2::pbkdf2_hmac::<Sha1>(password, salt, rounds, res),
            MessageDigest::Sha256(_) => pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, rounds, res),
            MessageDigest::Sha384(_) => pbkdf2::pbkdf2_hmac::<Sha384>(password, salt, rounds, res),
            MessageDigest::Sha512(_) => pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, rounds, res),
        };
    }
    pub fn hmac(&self, key: &[u8]) -> Result<self::Hmac, anyhow::Error> {
        use hmac::KeyInit;

        Ok(match self {
            MessageDigest::Sha1(_) => {
                self::Hmac::HmacSha1(hmac::Hmac::<Sha1>::new_from_slice(key)?)
            }
            MessageDigest::Sha256(_) => {
                self::Hmac::HmacSha256(hmac::Hmac::<Sha256>::new_from_slice(key)?)
            }
            MessageDigest::Sha384(_) => {
                self::Hmac::HmacSha384(hmac::Hmac::<Sha384>::new_from_slice(key)?)
            }
            MessageDigest::Sha512(_) => {
                self::Hmac::HmacSha512(hmac::Hmac::<Sha512>::new_from_slice(key)?)
            }
        })
    }
    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            MessageDigest::Sha1(_) => sha1::Sha1::digest(data).to_vec(),
            MessageDigest::Sha256(_) => sha2::Sha256::digest(data).to_vec(),
            MessageDigest::Sha384(_) => sha2::Sha384::digest(data).to_vec(),
            MessageDigest::Sha512(_) => sha2::Sha512::digest(data).to_vec(),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Pbes2HmacAeskwJweAlgorithm {
    /// PBES2 with HMAC SHA-256 and "A128KW" wrapping
    Pbes2Hs256A128kw,
    /// PBES2 with HMAC SHA-384 and "A192KW" wrapping
    Pbes2Hs384A192kw,
    /// PBES2 with HMAC SHA-512 and "A256KW" wrapping
    Pbes2Hs512A256kw,
}

impl Pbes2HmacAeskwJweAlgorithm {
    pub fn encrypter_from_bytes(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<Pbes2HmacAeskwJweEncrypter, JoseError> {
        (|| -> anyhow::Result<Pbes2HmacAeskwJweEncrypter> {
            let private_key = input.as_ref().to_vec();

            if private_key.len() == 0 {
                bail!("The key size must not be empty.");
            }

            Ok(Pbes2HmacAeskwJweEncrypter {
                algorithm: self.clone(),
                private_key,
                salt_len: 8,
                iter_count: 1000,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn encrypter_from_jwk(&self, jwk: &Jwk) -> Result<Pbes2HmacAeskwJweEncrypter, JoseError> {
        (|| -> anyhow::Result<Pbes2HmacAeskwJweEncrypter> {
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
                Some(Value::String(val)) => util::decode_base64_urlsafe_no_pad(val)?,
                Some(val) => bail!("A parameter k must be string type but {:?}", val),
                None => bail!("A parameter k is required."),
            };

            if k.len() == 0 {
                bail!("The key size must not be empty.");
            }

            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(Pbes2HmacAeskwJweEncrypter {
                algorithm: self.clone(),
                private_key: k,
                salt_len: 8,
                iter_count: 1000,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn decrypter_from_bytes(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<Pbes2HmacAeskwJweDecrypter, JoseError> {
        (|| -> anyhow::Result<Pbes2HmacAeskwJweDecrypter> {
            let private_key = input.as_ref().to_vec();

            if private_key.len() == 0 {
                bail!("The key size must not be empty.");
            }

            Ok(Pbes2HmacAeskwJweDecrypter {
                algorithm: self.clone(),
                private_key,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn decrypter_from_jwk(&self, jwk: &Jwk) -> Result<Pbes2HmacAeskwJweDecrypter, JoseError> {
        (|| -> anyhow::Result<Pbes2HmacAeskwJweDecrypter> {
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
                Some(Value::String(val)) => util::decode_base64_urlsafe_no_pad(val)?,
                Some(val) => bail!("A parameter k must be string type but {:?}", val),
                None => bail!("A parameter k is required."),
            };

            if k.len() == 0 {
                bail!("The key size must not be empty.");
            }

            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(Pbes2HmacAeskwJweDecrypter {
                algorithm: self.clone(),
                private_key: k,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            Self::Pbes2Hs256A128kw => HashAlgorithm::Sha256,
            Self::Pbes2Hs384A192kw => HashAlgorithm::Sha384,
            Self::Pbes2Hs512A256kw => HashAlgorithm::Sha512,
        }
    }

    fn derived_key_len(&self) -> usize {
        match self {
            Self::Pbes2Hs256A128kw => 16,
            Self::Pbes2Hs384A192kw => 24,
            Self::Pbes2Hs512A256kw => 32,
        }
    }
}

impl JweAlgorithm for Pbes2HmacAeskwJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::Pbes2Hs256A128kw => "PBES2-HS256+A128KW",
            Self::Pbes2Hs384A192kw => "PBES2-HS384+A192KW",
            Self::Pbes2Hs512A256kw => "PBES2-HS512+A256KW",
        }
    }

    fn box_clone(&self) -> Box<dyn JweAlgorithm> {
        Box::new(self.clone())
    }
}

impl Display for Pbes2HmacAeskwJweAlgorithm {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for Pbes2HmacAeskwJweAlgorithm {
    type Target = dyn JweAlgorithm;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct Pbes2HmacAeskwJweEncrypter {
    algorithm: Pbes2HmacAeskwJweAlgorithm,
    private_key: Vec<u8>,
    salt_len: usize,
    iter_count: usize,
    key_id: Option<String>,
}

impl Pbes2HmacAeskwJweEncrypter {
    pub fn set_salt_len(&mut self, salt_len: usize) {
        if salt_len < 8 {
            panic!("salt_len must be 8 or more: {}", salt_len);
        }
        self.salt_len = salt_len;
    }

    pub fn set_iter_count(&mut self, iter_count: usize) {
        if iter_count < 1000 {
            panic!("iter_count must be 1000 or more: {}", iter_count);
        }
        self.iter_count = iter_count;
    }

    pub fn set_key_id(&mut self, value: impl Into<String>) {
        self.key_id = Some(value.into());
    }

    pub fn remove_key_id(&mut self) {
        self.key_id = None;
    }
}

impl JweEncrypter for Pbes2HmacAeskwJweEncrypter {
    fn algorithm(&self) -> &dyn JweAlgorithm {
        &self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn compute_content_encryption_key<'a>(
        &'a self,
        _cencryption: &dyn JweContentEncryption,
        _in_header: &JweHeader,
        _out_header: &mut JweHeader,
    ) -> Result<Option<Cow<'a, [u8]>>, JoseError> {
        Ok(None)
    }

    fn encrypt(
        &self,
        key: &[u8],
        in_header: &JweHeader,
        out_header: &mut JweHeader,
    ) -> Result<Option<Vec<u8>>, JoseError> {
        (|| -> anyhow::Result<Option<Vec<u8>>> {
            let p2s = match in_header.claim("p2s") {
                Some(Value::String(val)) => {
                    let p2s = util::decode_base64_urlsafe_no_pad(val)?;
                    if p2s.len() < 8 {
                        bail!("The decoded value of p2s header claim must be 8 or more.");
                    }
                    p2s
                }
                Some(_) => bail!("The p2s header claim must be string."),
                None => {
                    let p2s = util::random_bytes(self.salt_len);
                    let p2s_b64 = util::encode_base64_urlsafe_nopad(&p2s);
                    out_header.set_claim("p2s", Some(Value::String(p2s_b64)))?;
                    p2s
                }
            };
            let p2c = match in_header.claim("p2c") {
                Some(Value::Number(val)) => match val.as_u64() {
                    Some(val) => usize::try_from(val)?,
                    None => bail!("Overflow u64 value: {}", val),
                },
                Some(_) => bail!("The apv header claim must be string."),
                None => {
                    let p2c = self.iter_count;
                    out_header.set_claim("p2c", Some(Value::Number(Number::from(p2c))))?;
                    p2c
                }
            };

            let mut salt = Vec::with_capacity(self.algorithm().name().len() + 1 + p2s.len());
            salt.extend_from_slice(self.algorithm().name().as_bytes());
            salt.push(0);
            salt.extend_from_slice(&p2s);

            let md = match &self.algorithm.hash_algorithm() {
                HashAlgorithm::Sha1 => MessageDigest::sha1(),
                HashAlgorithm::Sha256 => MessageDigest::sha256(),
                HashAlgorithm::Sha384 => MessageDigest::sha384(),
                HashAlgorithm::Sha512 => MessageDigest::sha512(),
            };
            let mut derived_key = vec![0; self.algorithm.derived_key_len()];
            #[cfg(feature = "openssl")]
            pkcs5::pbkdf2_hmac(&self.private_key, &salt, p2c, md, &mut derived_key)?;
            #[cfg(feature = "rustcrypto")]
            md.pbkdf2(&self.private_key, &salt, p2c as u32, &mut derived_key);
            let aes = match AesKey::new_encrypt(&derived_key) {
                Ok(val) => val,
                Err(_) => bail!("Failed to set a encryption key."),
            };

            let mut encrypted_key = vec![0; key.len() + 8];
            match aes::wrap_key(&aes, None, &mut encrypted_key, &key) {
                #[allow(unused)]
                Ok(val) =>
                {
                    #[cfg(feature = "openssl")]
                    if val < encrypted_key.len() {
                        encrypted_key.truncate(val);
                    }
                }
                Err(_) => bail!("Failed to wrap a key."),
            }

            Ok(Some(encrypted_key))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn box_clone(&self) -> Box<dyn JweEncrypter> {
        Box::new(self.clone())
    }
}

impl Deref for Pbes2HmacAeskwJweEncrypter {
    type Target = dyn JweEncrypter;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct Pbes2HmacAeskwJweDecrypter {
    algorithm: Pbes2HmacAeskwJweAlgorithm,
    private_key: Vec<u8>,
    key_id: Option<String>,
}

impl Pbes2HmacAeskwJweDecrypter {
    pub fn set_key_id(&mut self, value: impl Into<String>) {
        self.key_id = Some(value.into());
    }

    pub fn remove_key_id(&mut self) {
        self.key_id = None;
    }
}

impl JweDecrypter for Pbes2HmacAeskwJweDecrypter {
    fn algorithm(&self) -> &dyn JweAlgorithm {
        &self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn decrypt<'a>(
        &'a self,
        encrypted_key: Option<&[u8]>,
        _cencryption: &dyn JweContentEncryption,
        header: &JweHeader,
    ) -> Result<Cow<'a, [u8]>, JoseError> {
        (|| -> anyhow::Result<Cow<[u8]>> {
            let encrypted_key = match encrypted_key {
                Some(val) => val,
                None => bail!("A encrypted_key value is required."),
            };

            let p2s = match header.claim("p2s") {
                Some(Value::String(val)) => {
                    let p2s = util::decode_base64_urlsafe_no_pad(val)?;
                    if p2s.len() < 8 {
                        bail!("The decoded value of p2s header claim must be 8 or more.");
                    }
                    p2s
                }
                Some(_) => bail!("The p2s header claim must be string."),
                None => bail!("The p2s header claim is required."),
            };
            let p2c = match header.claim("p2c") {
                Some(Value::Number(val)) => match val.as_u64() {
                    Some(val) => usize::try_from(val)?,
                    None => bail!("Overflow u64 value: {}", val),
                },
                Some(_) => bail!("The p2c header claim must be string."),
                None => bail!("The p2c header claim is required."),
            };

            if p2c > 1000000 {
                bail!(
                    "The p2c value is too large. This is a possible DoS attack: {}",
                    p2c
                );
            }

            let mut salt = Vec::with_capacity(self.algorithm().name().len() + 1 + p2s.len());
            salt.extend_from_slice(self.algorithm().name().as_bytes());
            salt.push(0);
            salt.extend_from_slice(&p2s);

            let md = match &self.algorithm.hash_algorithm() {
                HashAlgorithm::Sha1 => MessageDigest::sha1(),
                HashAlgorithm::Sha256 => MessageDigest::sha256(),
                HashAlgorithm::Sha384 => MessageDigest::sha384(),
                HashAlgorithm::Sha512 => MessageDigest::sha512(),
            };
            let mut derived_key = vec![0; self.algorithm.derived_key_len()];
            #[cfg(feature = "openssl")]
            pkcs5::pbkdf2_hmac(&self.private_key, &salt, p2c, md, &mut derived_key)?;
            #[cfg(feature = "rustcrypto")]
            md.pbkdf2(&self.private_key, &salt, p2c as u32, &mut derived_key);

            let aes = match AesKey::new_decrypt(&derived_key) {
                Ok(val) => val,
                Err(_) => bail!("Failed to set a decryption key."),
            };

            let mut key = vec![0; encrypted_key.len() - 8];
            match aes::unwrap_key(&aes, None, &mut key, &encrypted_key) {
                #[allow(unused)]
                Ok(val) =>
                {
                    #[cfg(feature = "openssl")]
                    if val < key.len() {
                        key.truncate(val);
                    }
                }
                Err(_) => bail!("Failed to unwrap a key."),
            }

            Ok(Cow::Owned(key))
        })()
        .map_err(|err| JoseError::InvalidJweFormat(err))
    }

    fn box_clone(&self) -> Box<dyn JweDecrypter> {
        Box::new(self.clone())
    }
}

impl Deref for Pbes2HmacAeskwJweDecrypter {
    type Target = dyn JweDecrypter;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use serde_json::json;

    use super::Pbes2HmacAeskwJweAlgorithm;
    use crate::jwe::enc::aescbc_hmac::AescbcHmacJweEncryption;
    use crate::jwe::JweHeader;
    use crate::jwk::Jwk;
    use crate::util;

    #[test]
    fn encrypt_and_decrypt_pbes2_hmac() -> Result<()> {
        let enc = AescbcHmacJweEncryption::A128cbcHs256;

        for alg in vec![
            Pbes2HmacAeskwJweAlgorithm::Pbes2Hs256A128kw,
            Pbes2HmacAeskwJweAlgorithm::Pbes2Hs384A192kw,
            Pbes2HmacAeskwJweAlgorithm::Pbes2Hs512A256kw,
        ] {
            let mut header = JweHeader::new();
            header.set_content_encryption(enc.name());

            let jwk = {
                let key = util::random_bytes(8);
                let key = util::encode_base64_urlsafe_nopad(&key);

                let mut jwk = Jwk::new("oct");
                jwk.set_key_use("enc");
                jwk.set_parameter("k", Some(json!(key)))?;
                jwk
            };

            let encrypter = alg.encrypter_from_jwk(&jwk)?;
            let mut out_header = header.clone();
            let src_key = util::random_bytes(enc.key_len());
            let encrypted_key = encrypter.encrypt(&src_key, &header, &mut out_header)?;

            let decrypter = alg.decrypter_from_jwk(&jwk)?;

            let dst_key = decrypter.decrypt(encrypted_key.as_deref(), &enc, &out_header)?;

            assert_eq!(&src_key as &[u8], &dst_key as &[u8]);
        }

        Ok(())
    }

    #[test]
    fn reject_pbes2_hmac_with_too_large_p2c() -> Result<()> {
        let enc = AescbcHmacJweEncryption::A128cbcHs256;

        for alg in vec![
            Pbes2HmacAeskwJweAlgorithm::Pbes2Hs256A128kw,
            Pbes2HmacAeskwJweAlgorithm::Pbes2Hs384A192kw,
            Pbes2HmacAeskwJweAlgorithm::Pbes2Hs512A256kw,
        ] {
            let mut header = JweHeader::new();
            header.set_content_encryption(enc.name());

            let jwk = {
                let key = util::random_bytes(8);
                let key = util::encode_base64_urlsafe_nopad(&key);

                let mut jwk = Jwk::new("oct");
                jwk.set_key_use("enc");
                jwk.set_parameter("k", Some(json!(key)))?;
                jwk
            };

            let mut encrypter = alg.encrypter_from_jwk(&jwk)?;
            encrypter.set_iter_count(1000001);
            let mut out_header = header.clone();
            let src_key = util::random_bytes(enc.key_len());
            let encrypted_key = encrypter.encrypt(&src_key, &header, &mut out_header)?;

            let decrypter = alg.decrypter_from_jwk(&jwk)?;

            let err = decrypter
                .decrypt(encrypted_key.as_deref(), &enc, &out_header)
                .unwrap_err();
            assert_eq!(format!("{}", err), "Invalid JWE format: The p2c value is too large. This is a possible DoS attack: 1000001");
        }

        Ok(())
    }
}

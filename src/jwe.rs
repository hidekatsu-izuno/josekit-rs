pub mod alg;
pub mod enc;
pub mod zip;

use std::collections::BTreeSet;
use std::collections::{HashMap, BTreeMap};
use std::fmt::{Display, Debug};
use std::cmp::Eq;
use std::io;

use anyhow::bail;
use once_cell::sync::Lazy;
use openssl::rand;
use serde_json::{Map, Value};

use crate::jose::{JoseError, JoseHeader};
use crate::jwk::Jwk;
use crate::util::{self, SourceValue};

pub use crate::jwe::alg::aes::AesJweAlgorithm::A128Kw;
pub use crate::jwe::alg::aes::AesJweAlgorithm::A192Kw;
pub use crate::jwe::alg::aes::AesJweAlgorithm::A256Kw;

pub use crate::jwe::alg::aes_gcm::AesGcmJweAlgorithm::A128GcmKw;
pub use crate::jwe::alg::aes_gcm::AesGcmJweAlgorithm::A192GcmKw;
pub use crate::jwe::alg::aes_gcm::AesGcmJweAlgorithm::A256GcmKw;

pub use crate::jwe::alg::direct::DirectJweAlgorithm::Dir;

pub use crate::jwe::alg::direct_key::DirectKeyJweAlgorithm::EcdhEs;

pub use crate::jwe::alg::ecdh_es_aes::EcdhEsAesJweAlgorithm::EcdhEsA128Kw;
pub use crate::jwe::alg::ecdh_es_aes::EcdhEsAesJweAlgorithm::EcdhEsA192Kw;
pub use crate::jwe::alg::ecdh_es_aes::EcdhEsAesJweAlgorithm::EcdhEsA256Kw;

pub use crate::jwe::alg::pbes2_hmac_aes::Pbes2HmacAesJweAlgorithm::Pbes2HS256A128Kw;
pub use crate::jwe::alg::pbes2_hmac_aes::Pbes2HmacAesJweAlgorithm::Pbes2HS384A192Kw;
pub use crate::jwe::alg::pbes2_hmac_aes::Pbes2HmacAesJweAlgorithm::Pbes2HS512A256Kw;

pub use crate::jwe::alg::rsaes::RsaesJweAlgorithm::Rsa1_5;
pub use crate::jwe::alg::rsaes::RsaesJweAlgorithm::RsaOaep;
pub use crate::jwe::alg::rsaes::RsaesJweAlgorithm::RsaOaep256;

pub use crate::jwe::enc::aes_cbc_hmac::AesCbcHmacJweEncryption::A128CbcHS256;
pub use crate::jwe::enc::aes_cbc_hmac::AesCbcHmacJweEncryption::A192CbcHS384;
pub use crate::jwe::enc::aes_cbc_hmac::AesCbcHmacJweEncryption::A256CbcHS512;

pub use crate::jwe::enc::aes_gcm::AesGcmJweEncryption::A128Gcm;
pub use crate::jwe::enc::aes_gcm::AesGcmJweEncryption::A192Gcm;
pub use crate::jwe::enc::aes_gcm::AesGcmJweEncryption::A256Gcm;

pub use crate::jwe::zip::deflate::DeflateJweCompression::Def;

static DEFAULT_CONTEXT: Lazy<JweContext> = Lazy::new(|| JweContext::new());

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct JweContext {
    acceptable_criticals: BTreeSet<String>,
    compressions: BTreeMap<String, Box<dyn JweCompression>>,
    content_encryptions: BTreeMap<String, Box<dyn JweContentEncryption>>,
}

impl JweContext {
    pub fn new() -> Self {
        Self {
            acceptable_criticals: BTreeSet::new(),
            compressions: {
                let compressions: Vec<Box<dyn JweCompression>> = vec![
                    Box::new(Def)
                ];

                let mut map = BTreeMap::new();
                for compression in compressions {
                    map.insert(
                        compression.name().to_string(), 
                        compression,
                    );
                }
                map
            },
            content_encryptions: {
                let content_encryptions: Vec<Box<dyn JweContentEncryption>> = vec![
                    Box::new(A128CbcHS256),
                    Box::new(A192CbcHS384),
                    Box::new(A256CbcHS512),
                    Box::new(A128Gcm),
                    Box::new(A192Gcm),
                    Box::new(A256Gcm),
                ];

                let mut map = BTreeMap::new();
                for content_encryption in content_encryptions {
                    map.insert(
                        content_encryption.name().to_string(), 
                        content_encryption,
                    );
                }
                map
            },
        }
    }

    /// Test a critical header claim name is acceptable.
    ///
    /// # Arguments
    ///
    /// * `name` - a critical header claim name
    pub fn is_acceptable_critical(&self, name: &str) -> bool {
        self.acceptable_criticals.contains(name)
    }

    /// Add a acceptable critical header claim name
    ///
    /// # Arguments
    ///
    /// * `name` - a acceptable critical header claim name
    pub fn add_acceptable_critical(&mut self, name: &str) {
        self.acceptable_criticals.insert(name.to_string());
    }

    /// Remove a acceptable critical header claim name
    ///
    /// # Arguments
    ///
    /// * `name` - a acceptable critical header claim name
    pub fn remove_acceptable_critical(&mut self, name: &str) {
        self.acceptable_criticals.remove(name);
    }
    
    /// Get a compression algorithm for zip header claim value.
    ///
    /// # Arguments
    ///
    /// * `name` - a zip header claim name
    pub fn get_compression(&self, name: &str) -> Option<&dyn JweCompression> {
        match self.compressions.get(name) {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    /// Add a compression algorithm for zip header claim name.
    ///
    /// # Arguments
    ///
    /// * `compression` - a compression algorithm
    pub fn add_compression(&mut self, compression: Box<dyn JweCompression>) {
        self.compressions.insert(compression.name().to_string(), compression);
    }

    /// Remove a compression algorithm for zip header claim name.
    ///
    /// # Arguments
    ///
    /// * `name` - a zip header claim name
    pub fn remove_compression(&mut self, name: &str) {
        self.compressions.remove(name);
    }

    /// Get a content encryption algorithm for enc header claim value.
    ///
    /// # Arguments
    ///
    /// * `name` - a content encryption header claim name
    pub fn get_content_encryption(&self, name: &str) -> Option<&dyn JweContentEncryption> {
        match self.content_encryptions.get(name) {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    /// Add a content encryption algorithm for enc header claim name.
    ///
    /// # Arguments
    ///
    /// * `content_encryption` - a content encryption algorithm
    pub fn add_content_encryption(&mut self, content_encryption: Box<dyn JweContentEncryption>) {
        self.content_encryptions.insert(content_encryption.name().to_string(), content_encryption);
    }

    /// Remove a content encryption algorithm for enc header claim name.
    ///
    /// # Arguments
    ///
    /// * `name` - a enc header claim name
    pub fn remove_content_encryption(&mut self, name: &str) {
        self.content_encryptions.remove(name);
    }

    /// Return a representation of the data that is formatted by compact serialization.
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload data.
    /// * `header` - The JWS heaser claims.
    /// * `encrypter` - The JWS encrypter.
    pub fn serialize_compact(
        &self,
        payload: &[u8],
        header: &JweHeader,
        encrypter: &dyn JweEncrypter,
    ) -> Result<String, JoseError> {
        self.serialize_compact_with_selector(payload, header, |_header| Some(encrypter))
    }

    /// Return a representation of the data that is formatted by compact serialization.
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload data.
    /// * `header` - The JWS heaser claims.
    /// * `selector` - a function for selecting the signing algorithm.
    pub fn serialize_compact_with_selector<'a, F>(
        &self,
        payload: &[u8],
        header: &JweHeader,
        selector: F,
    ) -> Result<String, JoseError>
    where
        F: Fn(&JweHeader) -> Option<&'a dyn JweEncrypter>,
    {
        (|| -> anyhow::Result<String> {
            let encrypter = match selector(header) {
                Some(val) => val,
                None => bail!("A encrypter is not found."),
            };

            let content_encryption = match header.content_encryption() {
                Some(enc) => match self.get_content_encryption(enc) {
                    Some(val) => val,
                    None => bail!("A content encryption is not registered: {}", enc),
                },
                None => bail!("A enc header claim is required."),
            };

            let compression = match header.compression() {
                Some(zip) => match self.get_compression(zip) {
                    Some(val) => Some(val),
                    None => bail!("A compression algorithm is not registered: {}", zip),
                },
                None => None,
            };

            let mut header = header.claims_set().clone();
            header.insert(
                "alg".to_string(),
                Value::String(encrypter.algorithm().name().to_string()),
            );
            if let Some(key_id) = encrypter.key_id() {
                header.insert("kid".to_string(), Value::String(key_id.to_string()));
            }
            let header = serde_json::to_string(&header)?;

            let compressed;
            let content = if let Some(compression) = compression {
                compressed = compression.compress(payload)?;
                &compressed
            } else {
                payload
            };

            let mut iv = vec![0; content_encryption.iv_len()];
            rand::rand_bytes(&mut iv)?;

            let mut generated_key;
            let content_encryption_key = match encrypter.content_encryption_key() {
                Some(val) => val,
                None => {
                    generated_key = vec![0; content_encryption.mac_key_len() + content_encryption.enc_key_len()];
                    rand::rand_bytes(&mut generated_key)?;
                    &generated_key
                }
            };

            let encrypted_key = encrypter.encrypt(content_encryption_key)?;

            let enc_key = &content_encryption_key[content_encryption.mac_key_len()..];
            let ciphertext = content_encryption.encrypt(content, &iv, enc_key)?;

            let tag = if content_encryption.mac_key_len() > 0 {
                let mac_key = &content_encryption_key[0..content_encryption.mac_key_len()];
                let tag = content_encryption.sign(vec![
                    header.as_bytes(),
                    iv.as_slice(),
                    ciphertext.as_slice(),
                    &header.len().to_be_bytes(),
                ], mac_key)?;
                Some(tag)
            } else {
                None
            };
            
            let mut capacity = 4;
            capacity += util::ceiling(header.len() * 4, 3);
            if let Some(val) = &encrypted_key {
                capacity += util::ceiling(val.len() * 4, 3);
            }
            capacity += util::ceiling(iv.len() * 4, 3);
            capacity += util::ceiling(ciphertext.len() * 4, 3);
            if let Some(val) = &tag {
                capacity += util::ceiling(val.len() * 4, 3);
            }

            let mut message = String::with_capacity(capacity);
            base64::encode_config_buf(header, base64::URL_SAFE_NO_PAD, &mut message);
            message.push_str(".");
            if let Some(val) = encrypted_key {
                base64::encode_config_buf(val, base64::URL_SAFE_NO_PAD, &mut message);
            }
            message.push_str(".");
            base64::encode_config_buf(iv, base64::URL_SAFE_NO_PAD, &mut message);
            message.push_str(".");
            base64::encode_config_buf(ciphertext, base64::URL_SAFE_NO_PAD, &mut message);
            message.push_str(".");
            if let Some(val) = tag {
                base64::encode_config_buf(val, base64::URL_SAFE_NO_PAD, &mut message);
            }

            Ok(message)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err),
        })
    }

    /// Return a representation of the data that is formatted by flattened json serialization.
    ///
    /// # Arguments
    ///
    /// * `protected` - The JWE protected header claims.
    /// * `header` - The JWE unprotected header claims.
    /// * `payload` - The payload data.
    /// * `encrypter` - The JWS encrypter.
    pub fn serialize_flattened_json(
        &self,
        payload: &[u8],
        protected: Option<&JweHeader>,
        header: Option<&JweHeader>,
        encrypter: &dyn JweEncrypter,
    ) -> Result<String, JoseError> {
        self.serialize_flattened_json_with_selector(payload, protected, header, |_header| {
            Some(encrypter)
        })
    }

    /// Return a representation of the data that is formatted by flatted json serialization.
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload data.
    /// * `protected` - The JWS protected header claims.
    /// * `header` - The JWS unprotected header claims.
    /// * `selector` - a function for selecting the encrypting algorithm.
    pub fn serialize_flattened_json_with_selector<'a, F>(
        &self,
        payload: &[u8],
        protected: Option<&JweHeader>,
        header: Option<&JweHeader>,
        selector: F,
    ) -> Result<String, JoseError>
    where
        F: Fn(&JweHeader) -> Option<&'a dyn JweEncrypter>,
    {
        (|| -> anyhow::Result<String> {
            unimplemented!("JWE is not supported yet.");
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err),
        })
    }

    /// Deserialize the input that is formatted by compact serialization.
    ///
    /// # Arguments
    ///
    /// * `input` - The input data.
    /// * `decrypter` - The JWS decrypter.
    pub fn deserialize_compact(
        &self,
        input: &str,
        decrypter: &dyn JweDecrypter,
    ) -> Result<(Vec<u8>, JweHeader), JoseError> {
        self.deserialize_compact_with_selector(input, |_header| Ok(Some(decrypter)))
    }

    /// Deserialize the input that is formatted by compact serialization.
    ///
    /// # Arguments
    ///
    /// * `input` - The input data.
    /// * `selector` - a function for selecting the decrypting algorithm.
    pub fn deserialize_compact_with_selector<'a, F>(
        &self,
        input: &str,
        selector: F,
    ) -> Result<(Vec<u8>, JweHeader), JoseError>
    where
        F: Fn(&JweHeader) -> Result<Option<&'a dyn JweDecrypter>, JoseError>,
    {
        (|| -> anyhow::Result<(Vec<u8>, JweHeader)> {
            unimplemented!("JWE is not supported yet.");
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err),
        })
    }

    /// Deserialize the input that is formatted by flattened json serialization.
    ///
    /// # Arguments
    ///
    /// * `input` - The input data.
    /// * `header` - The decoded JWS header claims.
    /// * `decrypter` - The JWE decrypter.
    pub fn deserialize_json<'a>(
        &self,
        input: &str,
        decrypter: &'a dyn JweDecrypter,
    ) -> Result<(Vec<u8>, JweHeader), JoseError> {
        self.deserialize_json_with_selector(input, |header| {
            match header.algorithm() {
                Some(val) => {
                    let expected_alg = decrypter.algorithm().name();
                    if val != expected_alg {
                        return Ok(None);
                    }
                }
                _ => return Ok(None),
            }

            match decrypter.key_id() {
                Some(expected) => match header.key_id() {
                    Some(actual) if expected == actual => {}
                    _ => return Ok(None),
                },
                None => {}
            }

            Ok(Some(decrypter))
        })
    }

    /// Deserialize the input that is formatted by flattened json serialization.
    ///
    /// # Arguments
    ///
    /// * `input` - The input data.
    /// * `selector` - a function for selecting the decrypting algorithm.
    pub fn deserialize_json_with_selector<'a, F>(
        &self,
        input: &str,
        selector: F,
    ) -> Result<(Vec<u8>, JweHeader), JoseError>
    where
        F: Fn(&JweHeader) -> Result<Option<&'a dyn JweDecrypter>, JoseError>,
    {
        (|| -> anyhow::Result<(Vec<u8>, JweHeader)> {
            unimplemented!("JWE is not supported yet.");
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err),
        })
    }
}

/// Return a representation of the data that is formatted by compact serialization.
///
/// # Arguments
///
/// * `payload` - The payload data.
/// * `header` - The JWS heaser claims.
/// * `encrypter` - The JWS encrypter.
pub fn serialize_compact(
    payload: &[u8],
    header: &JweHeader,
    encrypter: &dyn JweEncrypter,
) -> Result<String, JoseError> {
    DEFAULT_CONTEXT.serialize_compact(payload, header, encrypter)
}

/// Return a representation of the data that is formatted by compact serialization.
///
/// # Arguments
///
/// * `payload` - The payload data.
/// * `header` - The JWS heaser claims.
/// * `selector` - a function for selecting the signing algorithm.
pub fn serialize_compact_with_selector<'a, F>(
    payload: &[u8],
    header: &JweHeader,
    selector: F,
) -> Result<String, JoseError>
where
    F: Fn(&JweHeader) -> Option<&'a dyn JweEncrypter>,
{
    DEFAULT_CONTEXT.serialize_compact_with_selector(payload, header, selector)
}

/// Return a representation of the data that is formatted by flattened json serialization.
///
/// # Arguments
///
/// * `protected` - The JWE protected header claims.
/// * `header` - The JWE unprotected header claims.
/// * `payload` - The payload data.
/// * `encrypter` - The JWS encrypter.
pub fn serialize_flattened_json(
    payload: &[u8],
    protected: Option<&JweHeader>,
    header: Option<&JweHeader>,
    encrypter: &dyn JweEncrypter,
) -> Result<String, JoseError> {
    DEFAULT_CONTEXT.serialize_flattened_json(payload, protected, header, encrypter)
}

/// Return a representation of the data that is formatted by flatted json serialization.
///
/// # Arguments
///
/// * `payload` - The payload data.
/// * `protected` - The JWS protected header claims.
/// * `header` - The JWS unprotected header claims.
/// * `selector` - a function for selecting the encrypting algorithm.
pub fn serialize_flattened_json_with_selector<'a, F>(
    payload: &[u8],
    protected: Option<&JweHeader>,
    header: Option<&JweHeader>,
    selector: F,
) -> Result<String, JoseError>
where
    F: Fn(&JweHeader) -> Option<&'a dyn JweEncrypter>,
{
    DEFAULT_CONTEXT.serialize_flattened_json_with_selector(payload, protected, header, selector)
}

/// Deserialize the input that is formatted by compact serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `decrypter` - The JWS decrypter.
pub fn deserialize_compact(
    input: &str,
    decrypter: &dyn JweDecrypter,
) -> Result<(Vec<u8>, JweHeader), JoseError> {
    DEFAULT_CONTEXT.deserialize_compact(input, decrypter)
}

/// Deserialize the input that is formatted by compact serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `selector` - a function for selecting the decrypting algorithm.
pub fn deserialize_compact_with_selector<'a, F>(
    input: &str,
    selector: F,
) -> Result<(Vec<u8>, JweHeader), JoseError>
where
    F: Fn(&JweHeader) -> Result<Option<&'a dyn JweDecrypter>, JoseError>,
{
    DEFAULT_CONTEXT.deserialize_compact_with_selector(input, selector)
}

/// Deserialize the input that is formatted by flattened json serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `header` - The decoded JWS header claims.
/// * `decrypter` - The JWE decrypter.
pub fn deserialize_json<'a>(
    input: &str,
    decrypter: &'a dyn JweDecrypter,
) -> Result<(Vec<u8>, JweHeader), JoseError> {
    DEFAULT_CONTEXT.deserialize_json(input, decrypter)
}

/// Deserialize the input that is formatted by flattened json serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `selector` - a function for selecting the decrypting algorithm.
pub fn deserialize_json_with_selector<'a, F>(
    input: &str,
    selector: F,
) -> Result<(Vec<u8>, JweHeader), JoseError>
where
    F: Fn(&JweHeader) -> Result<Option<&'a dyn JweDecrypter>, JoseError>,
{
    DEFAULT_CONTEXT.deserialize_json_with_selector(input, selector)
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct JweHeader {
    claims: Map<String, Value>,
    sources: HashMap<String, SourceValue>,
}

impl JweHeader {
    /// Return a new JweHeader instance.
    pub fn new() -> Self {
        Self {
            claims: Map::new(),
            sources: HashMap::new(),
        }
    }

    /// Set a value for content encryption header claim (enc).
    ///
    /// # Arguments
    ///
    /// * `value` - a content encryption
    pub fn set_content_encryption(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("enc".to_string(), Value::String(value));
    }

    /// Return the value for content encryption header claim (enc).
    pub fn content_encryption(&self) -> Option<&str> {
        match self.claims.get("enc") {
            Some(Value::String(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    /// Set a value for compression header claim (zip).
    ///
    /// # Arguments
    ///
    /// * `value` - a encryption
    pub fn set_compression(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("zip".to_string(), Value::String(value));
    }

    /// Return the value for compression header claim (zip).
    pub fn compression(&self) -> Option<&str> {
        match self.claims.get("zip") {
            Some(Value::String(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    /// Set a value for JWK set URL header claim (jku).
    ///
    /// # Arguments
    ///
    /// * `value` - a JWK set URL
    pub fn set_jwk_set_url(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("jku".to_string(), Value::String(value));
    }

    /// Return the value for JWK set URL header claim (jku).
    pub fn jwk_set_url(&self) -> Option<&str> {
        match self.claims.get("jku") {
            Some(Value::String(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    /// Set a value for JWK header claim (jwk).
    ///
    /// # Arguments
    ///
    /// * `value` - a JWK
    pub fn set_jwk(&mut self, value: Jwk) {
        let key = "jwk".to_string();
        self.claims
            .insert(key.clone(), Value::Object(value.as_ref().clone()));
        self.sources.insert(key, SourceValue::Jwk(value));
    }

    /// Return the value for JWK header claim (jwk).
    pub fn jwk(&self) -> Option<&Jwk> {
        match self.sources.get("jwk") {
            Some(SourceValue::Jwk(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    /// Set a value for X.509 URL header claim (x5u).
    ///
    /// # Arguments
    ///
    /// * `value` - a X.509 URL
    pub fn set_x509_url(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("x5u".to_string(), Value::String(value));
    }

    /// Return a value for a X.509 URL header claim (x5u).
    pub fn x509_url(&self) -> Option<&str> {
        match self.claims.get("x5u") {
            Some(Value::String(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    /// Set values for X.509 certificate chain header claim (x5c).
    ///
    /// # Arguments
    ///
    /// * `values` - X.509 certificate chain
    pub fn set_x509_certificate_chain(&mut self, values: Vec<Vec<u8>>) {
        let key = "x5c".to_string();
        let mut vec = Vec::with_capacity(values.len());
        for val in &values {
            vec.push(Value::String(base64::encode_config(
                &val,
                base64::URL_SAFE_NO_PAD,
            )));
        }
        self.claims.insert(key.clone(), Value::Array(vec));
        self.sources.insert(key, SourceValue::BytesArray(values));
    }

    /// Return values for a X.509 certificate chain header claim (x5c).
    pub fn x509_certificate_chain(&self) -> Option<&Vec<Vec<u8>>> {
        match self.sources.get("x5c") {
            Some(SourceValue::BytesArray(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    /// Set a value for X.509 certificate SHA-1 thumbprint header claim (x5t).
    ///
    /// # Arguments
    ///
    /// * `value` - A X.509 certificate SHA-1 thumbprint
    pub fn set_x509_certificate_sha1_thumbprint(&mut self, value: Vec<u8>) {
        let key = "x5t".to_string();
        let val = base64::encode_config(&value, base64::URL_SAFE_NO_PAD);
        self.claims.insert(key.clone(), Value::String(val));
        self.sources.insert(key, SourceValue::Bytes(value));
    }

    /// Return the value for X.509 certificate SHA-1 thumbprint header claim (x5t).
    pub fn x509_certificate_sha1_thumbprint(&self) -> Option<&Vec<u8>> {
        match self.sources.get("x5t") {
            Some(SourceValue::Bytes(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    /// Set a value for a x509 certificate SHA-256 thumbprint header claim (x5t#S256).
    ///
    /// # Arguments
    ///
    /// * `value` - A x509 certificate SHA-256 thumbprint
    pub fn set_x509_certificate_sha256_thumbprint(&mut self, value: Vec<u8>) {
        let key = "x5t#S256".to_string();
        let val = base64::encode_config(&value, base64::URL_SAFE_NO_PAD);

        self.claims.insert(key.clone(), Value::String(val));
        self.sources.insert(key, SourceValue::Bytes(value));
    }

    /// Return the value for X.509 certificate SHA-256 thumbprint header claim (x5t#S256).
    pub fn x509_certificate_sha256_thumbprint(&self) -> Option<&Vec<u8>> {
        match self.sources.get("x5t#S256") {
            Some(SourceValue::Bytes(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    /// Set a value for key ID header claim (kid).
    ///
    /// # Arguments
    ///
    /// * `value` - a key ID
    pub fn set_key_id(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("kid".to_string(), Value::String(value));
    }

    /// Return the value for key ID header claim (kid).
    pub fn key_id(&self) -> Option<&str> {
        match self.claims.get("kid") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for token type header claim (typ).
    ///
    /// # Arguments
    ///
    /// * `value` - a token type (e.g. "JWT")
    pub fn set_token_type(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("typ".to_string(), Value::String(value));
    }

    /// Return the value for token type header claim (typ).
    pub fn token_type(&self) -> Option<&str> {
        match self.claims.get("typ") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for content type header claim (cty).
    ///
    /// # Arguments
    ///
    /// * `value` - a content type (e.g. "JWT")
    pub fn set_content_type(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("cty".to_string(), Value::String(value));
    }

    /// Return the value for content type header claim (cty).
    pub fn content_type(&self) -> Option<&str> {
        match self.claims.get("cty") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set values for critical header claim (crit).
    ///
    /// # Arguments
    ///
    /// * `values` - critical claim names
    pub fn set_critical(&mut self, values: Vec<impl Into<String>>) {
        let key = "crit".to_string();
        let mut vec1 = Vec::with_capacity(values.len());
        let mut vec2 = Vec::with_capacity(values.len());
        for val in values {
            let val: String = val.into();
            vec1.push(Value::String(val.clone()));
            vec2.push(val);
        }
        self.claims.insert(key.clone(), Value::Array(vec1));
        self.sources.insert(key, SourceValue::StringArray(vec2));
    }

    /// Return values for critical header claim (crit).
    pub fn critical(&self) -> Option<&Vec<String>> {
        match self.sources.get("crit") {
            Some(SourceValue::StringArray(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }
}

impl JoseHeader for JweHeader {
    fn from_map(claims: Map<String, Value>) -> Result<Self, JoseError> {
        Ok(Self {
            claims,
            sources: HashMap::new(),
        })
    }

    fn claims_set(&self) -> &Map<String, Value> {
        &self.claims
    }

    fn set_claim(&mut self, key: &str, value: Option<Value>) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            match key {
                "alg" => bail!(
                    "The Unsecured {} header claim should not be setted expressly.",
                    key
                ),
                _ => match &value {
                    Some(_) => {
                        self.claims.insert(key.to_string(), value.unwrap());
                    }
                    None => {
                        self.claims.remove(key);
                    }
                },
            }

            Ok(())
        })()
        .map_err(|err| JoseError::InvalidJwtFormat(err))
    }
}

impl Into<Map<String, Value>> for JweHeader {
    fn into(self) -> Map<String, Value> {
        self.claims
    }
}

impl Display for JweHeader {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let val = serde_json::to_string(self.claims_set()).map_err(|_e| std::fmt::Error {})?;
        fmt.write_str(&val)
    }
}

pub trait JweAlgorithm {
    /// Return the "alg" (algorithm) header parameter value of JWE.
    fn name(&self) -> &str;
}

pub trait JweEncrypter {
    /// Return the source algorithm instance.
    fn algorithm(&self) -> &dyn JweAlgorithm;

    /// Return the source key ID.
    /// The default value is a value of kid parameter in JWK.
    fn key_id(&self) -> Option<&str>;

    /// Set a compared value for a kid header claim (kid).
    ///
    /// # Arguments
    ///
    /// * `key_id` - a key ID
    fn set_key_id(&mut self, key_id: &str);

    /// Remove a compared value for a kid header claim (kid).
    fn remove_key_id(&mut self);

    /// Return a content encryption key.
    fn content_encryption_key(&self) -> Option<&[u8]>;

    /// Return a encypted key data.
    /// # Arguments
    ///
    /// * `content_encryption_key` - a content encryption key
    fn encrypt(&self, content_encryption_key: &[u8]) -> Result<Option<Vec<u8>>, JoseError>;
}

pub trait JweDecrypter {
    /// Return the source algorithm instance.
    fn algorithm(&self) -> &dyn JweAlgorithm;

    /// Return the source key ID.
    /// The default value is a value of kid parameter in JWK.
    fn key_id(&self) -> Option<&str>;

    /// Set a compared value for a kid header claim (kid).
    ///
    /// # Arguments
    ///
    /// * `key_id` - a key ID
    fn set_key_id(&mut self, key_id: &str);

    /// Remove a compared value for a kid header claim (kid).
    fn remove_key_id(&mut self);

    /// Return a content encryption key.
    fn content_encryption_key(&self) -> Option<&[u8]>;

    /// Return a decrypted key data.
    ///
    /// # Arguments
    ///
    /// * `encrypted_key` - The encrypted key.
    fn decrypt(&self, encrypted_key: &[u8]) -> Result<Option<Vec<u8>>, JoseError>;
}

pub trait JweContentEncryption: Debug + Send + Sync {
    /// Return the "enc" (encryption) header parameter value of JWE.
    fn name(&self) -> &str;

    fn enc_key_len(&self) -> usize;

    fn mac_key_len(&self) -> usize;

    fn iv_len(&self) -> usize;

    fn encrypt(&self, message: &[u8], iv: &[u8], enc_key: &[u8]) -> Result<Vec<u8>, JoseError>;

    fn decrypt(&self, data: &[u8], iv: &[u8], enc_key: &[u8]) -> Result<Vec<u8>, JoseError>;

    fn sign(&self, message: Vec<&[u8]>, mac_key: &[u8]) -> Result<Vec<u8>, JoseError>;

    fn box_clone(&self) -> Box<dyn JweContentEncryption>;
}

impl PartialEq for Box<dyn JweContentEncryption> {
    fn eq(&self, other: &Self) -> bool {
        self == other
    }
}

impl Eq for Box<dyn JweContentEncryption> {
}

impl Clone for Box<dyn JweContentEncryption> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

pub trait JweCompression: Debug + Send + Sync {
    /// Return the "zip" (compression algorithm) header parameter value of JWE.
    fn name(&self) -> &str;

    fn compress(&self, message: &[u8]) -> Result<Vec<u8>, io::Error>;

    fn decompress(&self, message: &[u8]) -> Result<Vec<u8>, io::Error>;

    fn box_clone(&self) -> Box<dyn JweCompression>;
}

impl PartialEq for Box<dyn JweCompression> {
    fn eq(&self, other: &Self) -> bool {
        self == other
    }
}

impl Eq for Box<dyn JweCompression> {
}

impl Clone for Box<dyn JweCompression> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

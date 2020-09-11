use std::cmp::Eq;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

use anyhow::bail;
use serde_json::{Map, Value};

use crate::jose::{JoseError, JoseHeader};
use crate::jwe::enc::{A128CbcHS256, A128Gcm, A192CbcHS384, A192Gcm, A256CbcHS512, A256Gcm};
use crate::jwe::zip::Def;
use crate::jwe::{JweCompression, JweContentEncryption, JweDecrypter, JweEncrypter, JweHeader};
use crate::util;

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
                let compressions: Vec<Box<dyn JweCompression>> = vec![Box::new(Def)];

                let mut map = BTreeMap::new();
                for compression in compressions {
                    map.insert(compression.name().to_string(), compression);
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
                    map.insert(content_encryption.name().to_string(), content_encryption);
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
        self.compressions
            .insert(compression.name().to_string(), compression);
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
        self.content_encryptions
            .insert(content_encryption.name().to_string(), content_encryption);
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

            let cencryption = match header.content_encryption() {
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

            let mut header = header.clone();

            let (key, encrypted_key) = encrypter.encrypt(&mut header, cencryption.key_len())?;
            if let None = header.claim("kid") {
                if let Some(key_id) = encrypter.key_id() {
                    header.set_key_id(key_id);
                }
            }
            let header_bytes = serde_json::to_vec(header.claims_set())?;
            let header_b64 = base64::encode_config(header_bytes, base64::URL_SAFE_NO_PAD);

            let compressed;
            let content = if let Some(compression) = compression {
                compressed = compression.compress(payload)?;
                &compressed
            } else {
                payload
            };

            let iv_vec;
            let iv = if cencryption.iv_len() > 0 {
                iv_vec = util::rand_bytes(cencryption.iv_len());
                Some(iv_vec.as_slice())
            } else {
                None
            };

            let (ciphertext, tag) =
                cencryption.encrypt(&key, iv, content, header_b64.as_bytes())?;

            let mut capacity = 4;
            capacity += header_b64.len();
            if let Some(val) = &encrypted_key {
                capacity += util::ceiling(val.len() * 4, 3);
            }
            if let Some(val) = iv {
                capacity += util::ceiling(val.len() * 4, 3);
            }
            capacity += util::ceiling(ciphertext.len() * 4, 3);
            if let Some(val) = &tag {
                capacity += util::ceiling(val.len() * 4, 3);
            }

            let mut message = String::with_capacity(capacity);
            message.push_str(&header_b64);
            message.push_str(".");
            if let Some(val) = &encrypted_key {
                base64::encode_config_buf(val, base64::URL_SAFE_NO_PAD, &mut message);
            }
            message.push_str(".");
            if let Some(val) = iv {
                base64::encode_config_buf(val, base64::URL_SAFE_NO_PAD, &mut message);
            }
            message.push_str(".");
            base64::encode_config_buf(ciphertext, base64::URL_SAFE_NO_PAD, &mut message);
            message.push_str(".");
            if let Some(val) = &tag {
                base64::encode_config_buf(val, base64::URL_SAFE_NO_PAD, &mut message);
            }

            Ok(message)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJweFormat(err),
        })
    }

    /// Return a representation of the data that is formatted by flattened json serialization.
    ///
    /// # Arguments
    ///
    /// * `protected` - The JWE protected header claims.
    /// * `unprotected` - The JWE unprotected header claims.
    /// * `header` - The JWE unprotected header claims per recipient.
    /// * `aad` - The JWE additional authenticated data.
    /// * `payload` - The payload data.
    /// * `encrypter` - The JWS encrypter.
    pub fn serialize_flattened_json(
        &self,
        payload: &[u8],
        protected: Option<&JweHeader>,
        unprotected: Option<&JweHeader>,
        header: Option<&JweHeader>,
        aad: Option<&[u8]>,
        encrypter: &dyn JweEncrypter,
    ) -> Result<String, JoseError> {
        self.serialize_flattened_json_with_selector(
            payload,
            protected,
            unprotected,
            header,
            aad,
            |_header| Some(encrypter),
        )
    }

    /// Return a representation of the data that is formatted by flatted json serialization.
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload data.
    /// * `protected` - The JWS protected header claims.
    /// * `unprotected` - The JWE unprotected header claims.
    /// * `header` - The JWE unprotected header claims per recipient.
    /// * `aad` - The JWE additional authenticated data.
    /// * `selector` - a function for selecting the encrypting algorithm.
    pub fn serialize_flattened_json_with_selector<'a, F>(
        &self,
        payload: &[u8],
        protected: Option<&JweHeader>,
        unprotected: Option<&JweHeader>,
        header: Option<&JweHeader>,
        aad: Option<&[u8]>,
        selector: F,
    ) -> Result<String, JoseError>
    where
        F: Fn(&JweHeader) -> Option<&'a dyn JweEncrypter>,
    {
        (|| -> anyhow::Result<String> {
            let mut protected = match protected {
                Some(val) => val.clone(),
                None => JweHeader::new(),
            };

            let mut merged_map = protected.claims_set().clone();

            if let Some(val) = unprotected {
                for (key, value) in val.claims_set() {
                    if merged_map.contains_key(key) {
                        bail!("Duplicate key exists: {}", key);
                    }
                    merged_map.insert(key.clone(), value.clone());
                }
            }

            if let Some(val) = header {
                for (key, value) in val.claims_set() {
                    if merged_map.contains_key(key) {
                        bail!("Duplicate key exists: {}", key);
                    }
                    merged_map.insert(key.clone(), value.clone());
                }
            }

            let merged = JweHeader::from_map(merged_map)?;
            let encrypter = match selector(&merged) {
                Some(val) => val,
                None => bail!("A encrypter is not found."),
            };

            let cencryption = match merged.content_encryption() {
                Some(enc) => match self.get_content_encryption(enc) {
                    Some(val) => val,
                    None => bail!("A content encryption is not registered: {}", enc),
                },
                None => bail!("A enc header claim is required."),
            };

            let compression = match merged.compression() {
                Some(zip) => match self.get_compression(zip) {
                    Some(val) => Some(val),
                    None => bail!("A compression algorithm is not registered: {}", zip),
                },
                None => None,
            };

            let compressed;
            let content = if let Some(compression) = compression {
                compressed = compression.compress(payload)?;
                &compressed
            } else {
                payload
            };

            let (key, encrypted_key) = encrypter.encrypt(&mut protected, cencryption.key_len())?;
            if let None = merged.claim("kid") {
                if let Some(key_id) = encrypter.key_id() {
                    protected.set_key_id(key_id);
                }
            }
            let protected = serde_json::to_vec(protected.claims_set())?;

            let iv_vec;
            let iv = if cencryption.iv_len() > 0 {
                iv_vec = util::rand_bytes(cencryption.iv_len());
                Some(iv_vec.as_slice())
            } else {
                None
            };

            let protected_b64 = base64::encode_config(protected, base64::URL_SAFE_NO_PAD);
            let (full_aad, aad_b64) = if let Some(val) = aad {
                let aad_b64 = base64::encode_config(val, base64::URL_SAFE_NO_PAD);
                (format!("{}.{}", &protected_b64, &aad_b64), Some(aad_b64))
            } else {
                (format!("{}.", &protected_b64), None)
            };

            let (ciphertext, tag) = cencryption.encrypt(&key, iv, content, full_aad.as_bytes())?;

            let mut json = String::new();
            json.push_str("{\"protected\":\"");
            json.push_str(&protected_b64);
            json.push_str("\"");

            if let Some(val) = unprotected {
                let unprotected = serde_json::to_string(val.claims_set())?;
                json.push_str(",\"unprotected\":");
                json.push_str(&unprotected);
            }

            if let Some(val) = header {
                let header = serde_json::to_string(val.claims_set())?;
                json.push_str(",\"header\":");
                json.push_str(&header);
            }

            json.push_str(",\"encrypted_key\":\"");
            if let Some(val) = encrypted_key {
                base64::encode_config_buf(&val, base64::URL_SAFE_NO_PAD, &mut json);
            }
            json.push_str("\"");

            if let Some(val) = aad_b64 {
                json.push_str(",\"aad\":\"");
                json.push_str(&val);
                json.push_str("\"");
            }

            json.push_str(",\"iv\":\"");
            if let Some(val) = iv {
                base64::encode_config_buf(&val, base64::URL_SAFE_NO_PAD, &mut json);
            }
            json.push_str("\"");

            json.push_str(",\"ciphertext\":\"");
            base64::encode_config_buf(&ciphertext, base64::URL_SAFE_NO_PAD, &mut json);
            json.push_str("\"");

            json.push_str(",\"tag\":\"");
            if let Some(val) = tag {
                base64::encode_config_buf(&val, base64::URL_SAFE_NO_PAD, &mut json);
            }
            json.push_str("\"}");

            Ok(json)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJweFormat(err),
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
            let indexies: Vec<usize> = input
                .char_indices()
                .filter(|(_, c)| c == &'.')
                .map(|(i, _)| i)
                .collect();
            if indexies.len() != 4 {
                bail!(
                    "The compact serialization form of JWE must be five parts separated by colon."
                );
            }

            let header_b64 = &input[0..indexies[0]];

            let encrypted_key_b64 = &input[(indexies[0] + 1)..(indexies[1])];
            let encrypted_key_vec;
            let encrypted_key = if encrypted_key_b64.len() > 0 {
                encrypted_key_vec =
                    base64::decode_config(encrypted_key_b64, base64::URL_SAFE_NO_PAD)?;
                Some(encrypted_key_vec.as_slice())
            } else {
                None
            };

            let iv_b64 = &input[(indexies[1] + 1)..(indexies[2])];
            let iv_vec;
            let iv = if iv_b64.len() > 0 {
                iv_vec = base64::decode_config(iv_b64, base64::URL_SAFE_NO_PAD)?;
                Some(iv_vec.as_slice())
            } else {
                None
            };

            let ciphertext_b64 = &input[(indexies[2] + 1)..(indexies[3])];
            let ciphertext = base64::decode_config(ciphertext_b64, base64::URL_SAFE_NO_PAD)?;

            let tag_b64 = &input[(indexies[3] + 1)..];
            let tag_vec;
            let tag = if tag_b64.len() > 0 {
                tag_vec = base64::decode_config(tag_b64, base64::URL_SAFE_NO_PAD)?;
                Some(tag_vec.as_slice())
            } else {
                None
            };

            let header = base64::decode_config(header_b64, base64::URL_SAFE_NO_PAD)?;
            let merged: Map<String, Value> = serde_json::from_slice(&header)?;
            let merged = JweHeader::from_map(merged)?;

            let decrypter = match selector(&merged)? {
                Some(val) => val,
                None => bail!("A decrypter is not found."),
            };

            let cencryption = match merged.claim("enc") {
                Some(Value::String(val)) => match self.get_content_encryption(val) {
                    Some(val2) => val2,
                    None => bail!("A content encryption is not registered: {}", val),
                },
                Some(_) => bail!("A enc header claim must be a string."),
                None => bail!("A enc header claim is required."),
            };

            let compression = match merged.claim("zip") {
                Some(Value::String(val)) => match self.get_compression(val) {
                    Some(val2) => Some(val2),
                    None => bail!("A compression algorithm is not registered: {}", val),
                },
                Some(_) => bail!("A enc header claim must be a string."),
                None => None,
            };

            match merged.algorithm() {
                Some(val) => {
                    let expected_alg = decrypter.algorithm().name();
                    if val != expected_alg {
                        bail!("The JWE alg header claim is not {}: {}", expected_alg, val);
                    }
                }
                None => bail!("The JWE alg header claim is required."),
            }

            match decrypter.key_id() {
                Some(expected) => match merged.key_id() {
                    Some(actual) if expected == actual => {}
                    Some(actual) => bail!("The JWE kid header claim is mismatched: {}", actual),
                    None => bail!("The JWE kid header claim is required."),
                },
                None => {}
            }

            let key = decrypter.decrypt(&merged, encrypted_key, cencryption.key_len())?;
            let content = cencryption.decrypt(&key, iv, &ciphertext, header_b64.as_bytes(), tag)?;
            let content = match compression {
                Some(val) => val.decompress(&content)?,
                None => content,
            };

            Ok((content, merged))
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJweFormat(err),
        })
    }

    /// Deserialize the input that is formatted by flattened json serialization.
    ///
    /// # Arguments
    ///
    /// * `input` - The input data.
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
            let mut map: Map<String, Value> = serde_json::from_str(input)?;

            let (protected, protected_b64) = match map.remove("protected") {
                Some(Value::String(val)) => {
                    if val.len() == 0 {
                        bail!("The protected field must be empty.");
                    }
                    let vec = base64::decode_config(&val, base64::URL_SAFE_NO_PAD)?;
                    let json: Map<String, Value> = serde_json::from_slice(&vec)?;
                    (Some(json), Some(val))
                }
                Some(_) => bail!("The protected field must be string."),
                None => (None, None),
            };
            let unprotected = match map.remove("unprotected") {
                Some(Value::String(val)) => {
                    if val.len() == 0 {
                        bail!("The unprotected field must be empty.");
                    }
                    let json: Map<String, Value> = serde_json::from_str(&val)?;
                    Some(json)
                }
                Some(_) => bail!("The unprotected field must be string."),
                None => None,
            };
            let aad_b64 = match map.remove("aad") {
                Some(Value::String(val)) => {
                    if val.len() == 0 {
                        bail!("The aad field must be empty.");
                    }
                    base64::decode_config(&val, base64::URL_SAFE_NO_PAD)?;
                    Some(val)
                }
                Some(_) => bail!("The aad field must be string."),
                None => None,
            };
            let iv_vec;
            let iv = match map.remove("iv") {
                Some(Value::String(val)) => {
                    if val.len() == 0 {
                        bail!("The iv field must be empty.");
                    }
                    iv_vec = base64::decode_config(&val, base64::URL_SAFE_NO_PAD)?;
                    Some(iv_vec.as_slice())
                }
                Some(_) => bail!("The iv field must be string."),
                None => None,
            };
            let ciphertext = match map.remove("ciphertext") {
                Some(Value::String(val)) => {
                    if val.len() == 0 {
                        bail!("The ciphertext field must be empty.");
                    }
                    base64::decode_config(&val, base64::URL_SAFE_NO_PAD)?
                }
                Some(_) => bail!("The ciphertext field must be string."),
                None => bail!("The ciphertext field is required."),
            };
            let tag_vec;
            let tag = match map.remove("tag") {
                Some(Value::String(val)) => {
                    if val.len() == 0 {
                        bail!("The tag field must be empty.");
                    }
                    tag_vec = base64::decode_config(&val, base64::URL_SAFE_NO_PAD)?;
                    Some(tag_vec.as_slice())
                }
                Some(_) => bail!("The tag field must be string."),
                None => None,
            };

            let recipients = match map.remove("recipients") {
                Some(Value::Array(vals)) => {
                    if vals.len() == 0 {
                        bail!("The recipients field must be empty.");
                    }
                    let mut vec = Vec::with_capacity(vals.len());
                    for val in vals {
                        if let Value::Object(val) = val {
                            vec.push(val);
                        } else {
                            bail!("The recipients field must be a array of object.");
                        }
                    }
                    vec
                }
                Some(_) => bail!("The recipients field must be a array."),
                None => {
                    let mut vec = Vec::with_capacity(1);
                    vec.push(map);
                    vec
                }
            };

            for mut recipient in recipients {
                let header = recipient.remove("header");

                let encrypted_key_vec;
                let encrypted_key = match recipient.get("encrypted_key") {
                    Some(Value::String(val)) => {
                        if val.len() == 0 {
                            bail!("The encrypted_key field must be empty.");
                        }
                        encrypted_key_vec = base64::decode_config(&val, base64::URL_SAFE_NO_PAD)?;
                        Some(encrypted_key_vec.as_slice())
                    }
                    Some(_) => bail!("The encrypted_key field must be a string."),
                    None => None,
                };

                let mut merged = match header {
                    Some(Value::Object(val)) => val,
                    Some(_) => bail!("The protected field must be a object."),
                    None => Map::new(),
                };

                if let Some(val) = &unprotected {
                    for (key, value) in val {
                        if merged.contains_key(key) {
                            bail!("A duplicate key exists: {}", key);
                        } else {
                            merged.insert(key.clone(), value.clone());
                        }
                    }
                }

                if let Some(val) = &protected {
                    for (key, value) in val {
                        if merged.contains_key(key) {
                            bail!("A duplicate key exists: {}", key);
                        } else {
                            merged.insert(key.clone(), value.clone());
                        }
                    }
                }

                let merged = JweHeader::from_map(merged)?;

                let decrypter = match selector(&merged)? {
                    Some(val) => val,
                    None => continue,
                };

                let cencryption = match merged.claim("enc") {
                    Some(Value::String(val)) => match self.get_content_encryption(val) {
                        Some(val2) => val2,
                        None => bail!("A content encryption is not registered: {}", val),
                    },
                    Some(_) => bail!("A enc header claim must be string."),
                    None => bail!("A enc header claim is required."),
                };

                let compression = match merged.claim("zip") {
                    Some(Value::String(val)) => match self.get_compression(val) {
                        Some(val2) => Some(val2),
                        None => bail!("A compression algorithm is not registered: {}", val),
                    },
                    Some(_) => bail!("A enc header claim must be string."),
                    None => None,
                };

                match merged.algorithm() {
                    Some(val) => {
                        let expected_alg = decrypter.algorithm().name();
                        if val != expected_alg {
                            bail!("The JWE alg header claim is not {}: {}", expected_alg, val);
                        }
                    }
                    None => bail!("The JWE alg header claim is required."),
                }

                match decrypter.key_id() {
                    Some(expected) => match merged.key_id() {
                        Some(actual) if expected == actual => {}
                        Some(actual) => bail!("The JWE kid header claim is mismatched: {}", actual),
                        None => bail!("The JWE kid header claim is required."),
                    },
                    None => {}
                }

                let mut full_aad = match protected_b64 {
                    Some(val) => val,
                    None => String::new(),
                };
                if let Some(val) = aad_b64 {
                    full_aad.push_str(".");
                    full_aad.push_str(&val);
                }

                let key = decrypter.decrypt(&merged, encrypted_key, cencryption.key_len())?;
                let content =
                    cencryption.decrypt(&key, iv, &ciphertext, full_aad.as_bytes(), tag)?;
                let content = match compression {
                    Some(val) => val.decompress(&content)?,
                    None => content,
                };

                return Ok((content, merged));
            }

            bail!("A recipient that matched the header claims is not found.");
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJweFormat(err),
        })
    }
}

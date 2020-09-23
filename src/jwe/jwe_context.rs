use std::borrow::Cow;
use std::cmp::Eq;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;

use anyhow::bail;
use serde_json::{Map, Value};

use crate::jwe::enc::{A128CBC_HS256, A128GCM, A192CBC_HS384, A192GCM, A256CBC_HS512, A256GCM};
use crate::jwe::zip::Def;
use crate::jwe::{JweCompression, JweContentEncryption, JweDecrypter, JweEncrypter, JweHeader};
use crate::util;
use crate::{JoseError, JoseHeader};

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
                    Box::new(A128CBC_HS256),
                    Box::new(A192CBC_HS384),
                    Box::new(A256CBC_HS512),
                    Box::new(A128GCM),
                    Box::new(A192GCM),
                    Box::new(A256GCM),
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

            let mut out_header = header.clone();

            let key_len = cencryption.key_len();
            let key = match encrypter.compute_content_encryption_key(cencryption, &header, &mut out_header)? {
                Some(val) => val,
                None => Cow::Owned(util::rand_bytes(key_len)),
            };

            let encrypted_key = encrypter.encrypt(&key, &header, &mut out_header)?;
            if let None = header.claim("kid") {
                if let Some(key_id) = encrypter.key_id() {
                    out_header.set_key_id(key_id);
                }
            }

            out_header.set_algorithm(encrypter.algorithm().name());

            let header_bytes = serde_json::to_vec(out_header.claims_set())?;
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
    /// * `payload` - The payload data.
    /// * `protected` - The JWS protected header claims.
    /// * `unprotected` - The JWS unprotected header claims.
    /// * `recipients` - The JWE header claims and the JWE encrypter pair for recipients.
    /// * `aad` - The JWE additional authenticated data.
    pub fn serialize_general_json(
        &self,
        payload: &[u8],
        protected: Option<&JweHeader>,
        unprotected: Option<&JweHeader>,
        recipients: &[(
            Option<&JweHeader>,
            &dyn JweEncrypter,
        )],
        aad: Option<&[u8]>,
    ) -> Result<String, JoseError> {
        self.serialize_general_json_with_selector(
            payload,
            protected,
            unprotected,
            recipients.iter()
                .map(|(header, _)| header.as_deref())
                .collect::<Vec<Option<&JweHeader>>>()
                .as_slice(),
            aad,
            |i, _header| Some(recipients[i].1),
        )
    }

    /// Return a representation of the data that is formatted by flattened json serialization.
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload data.
    /// * `protected` - The JWS protected header claims.
    /// * `unprotected` - The JWS unprotected header claims.
    /// * `recipients` - The JWE header claims for recipients.
    /// * `aad` - The JWE additional authenticated data.
    /// * `selector` - a function for selecting the encrypting algorithm.
    pub fn serialize_general_json_with_selector<'a, F>(
        &self,
        payload: &[u8],
        protected: Option<&JweHeader>,
        unprotected: Option<&JweHeader>,
        recipients: &[Option<&JweHeader>],
        aad: Option<&[u8]>,
        selector: F,
    ) -> Result<String, JoseError>
    where
        F: Fn(usize, &JweHeader) -> Option<&'a dyn JweEncrypter>,
    {
        (|| -> anyhow::Result<String> {
            if recipients.len() == 0 {
                bail!("A size of recipients must be 1 or more: {}", recipients.len());
            }

            let mut merged_map = match protected {
                Some(val) => val.claims_set().clone(),
                None => Map::new(),
            };

            let compressed;
            let content = match merged_map.get("zip") {
                Some(Value::String(val)) => match self.get_compression(val) {
                    Some(val) => {
                        compressed = val.compress(payload).unwrap();
                        &compressed
                    },
                    None => bail!("A compression algorithm is not registered: {}", val),
                },
                Some(_) => bail!("A zip header claim must be a string."),
                None => payload,
            };

            if let Some(val) = unprotected {
                for (key, value) in val.claims_set() {
                    if merged_map.contains_key(key) {
                        bail!("Duplicate key exists: {}", key);
                    }
                    merged_map.insert(key.clone(), value.clone());
                }
            }

            let protected_b64 = match protected {
                Some(val) if val.len() > 0 => {
                    let protected_json = serde_json::to_vec(val.claims_set()).unwrap();
                    Some(base64::encode_config(protected_json, base64::URL_SAFE_NO_PAD))
                },
                _ => None,
            };

            let mut encrypter_list = Vec::new();
            let mut merged_list = Vec::new();
            let mut header_list = Vec::new();

            let mut cencryption: Option<&dyn JweContentEncryption> = None;
            let mut key: Option<Cow<[u8]>> = None;
            for (i, header) in recipients.iter().enumerate() {
                let merged_map = match header {
                    Some(val) => {
                        let mut merged_map = merged_map.clone();
                        for (key, value) in val.claims_set() {
                            if merged_map.contains_key(key) {
                                bail!("Duplicate key exists: {}", key);
                            }
                            merged_map.insert(key.clone(), value.clone());
                        }
                        merged_map
                    },
                    None => merged_map.clone(),
                };

                let i_enc = match merged_map.get("enc") {
                    Some(Value::String(val)) => val,
                    Some(_) => bail!("A enc header claim must be a string."),
                    None => bail!("A enc header claim must be required."),
                };

                let i_cencryption = if let Some(val) = cencryption {
                    if val.name() != i_enc {
                        bail!("All of the enc header claim must be same.");
                    }
                    val
                } else {
                    match self.get_content_encryption(i_enc) {
                        Some(val) => {
                            cencryption = Some(val);
                            val
                        },
                        None => bail!("A content encryption is not registered: {}", i_enc),
                    }
                };

                let mut merged = JweHeader::from_map(merged_map)?;
                let encrypter = match selector(i, &merged) {
                    Some(val) => val,
                    None => bail!("A encrypter is not found."),
                };
                merged.set_algorithm(encrypter.algorithm().name());

                let mut header = match *header {
                    Some(val) => val.clone(),
                    None => JweHeader::new(),
                };

                let i_key = encrypter.compute_content_encryption_key(
                    i_cencryption,
                    &merged,
                    &mut header,
                )?;

                match i_key {
                    Some(val) => {
                        if let Some(val2) = key {
                            if val.as_ref() != val2.as_ref() {
                                bail!("A content encryption key must be only one.");
                            }
                        }
                        key = Some(val);
                    },
                    None => {},
                }

                encrypter_list.push(encrypter);
                header_list.push(header);
                merged_list.push(merged);
            }

            let cencryption = match cencryption {
                Some(val) => val,
                None => bail!("A enc header claim is required."),
            };

            let key = match key {
                Some(val) => val,
                None => Cow::Owned(util::rand_bytes(cencryption.key_len())),
            };

            let iv = if cencryption.iv_len() > 0 {
                Some(util::rand_bytes(cencryption.iv_len()))
            } else {
                None
            };

            let aad_b64 = match aad {
                Some(val) => Some(base64::encode_config(val, base64::URL_SAFE_NO_PAD)),
                None => None
            };

            let mut full_aad_capacity = 1;
            if let Some(val) = &protected_b64 {
                full_aad_capacity += val.len();
            }
            if let Some(val) = &aad_b64 {
                full_aad_capacity += val.len();
            }
            let mut full_aad = String::with_capacity(full_aad_capacity);
            if let Some(val) = &protected_b64 {
                full_aad.push_str(&val);
            }
            full_aad.push_str(".");
            if let Some(val) = &aad_b64 {
                full_aad.push_str(&val);
            }

            let (ciphertext, tag) = cencryption.encrypt(
                &key, 
                iv.as_deref(),
                content, 
                full_aad.as_bytes()
            )?;

            let mut json = String::new();
            json.push_str("{\"protected\":\"");
            if let Some(val) = &protected_b64 {
                json.push_str(val);
            }
            json.push_str("\"");
            
            json.push_str(",\"unprotected\":");
            if let Some(val) = unprotected {
                let unprotected_json = serde_json::to_string(val.claims_set()).unwrap();
                json.push_str(&unprotected_json);
            }

            json.push_str(",\"recipients\":[");
            for i in 0..=recipients.len() {
                if i > 0 {
                    json.push_str(",");
                }

                let encrypter = encrypter_list[i];
                let merged = &merged_list[i];
                let mut header = &mut header_list[i];

                let encrypted_key = encrypter.encrypt(&key, &merged, &mut header)?;

                if let None = merged.claim("kid") {
                    if let Some(key_id) = encrypter.key_id() {
                        header.set_key_id(key_id);
                    }
                }
                header.set_algorithm(encrypter.algorithm().name());

                let header_json = serde_json::to_string(header_list[i].claims_set())?;
                json.push_str("{\"header\":\"");
                json.push_str(&header_json);
                json.push_str("\"");

                json.push_str(",\"encrypted_key\":\"");
                if let Some(val) = encrypted_key {
                    base64::encode_config_buf(&val, base64::URL_SAFE_NO_PAD, &mut json);
                }
                json.push_str("\"}");
            }
            json.push_str("]");

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
            json.push_str("\"");

            json.push_str("}");

            Ok(json)
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

            let encrypter = match selector(&merged) {
                Some(val) => val,
                None => bail!("A encrypter is not found."),
            };

            let compressed;
            let content = if let Some(compression) = compression {
                compressed = compression.compress(payload)?;
                &compressed
            } else {
                payload
            };

            let key = match encrypter.compute_content_encryption_key(
                cencryption, &merged, &mut protected)? {
                Some(val) => val,
                None => Cow::Owned(util::rand_bytes(cencryption.key_len())),
            };

            let encrypted_key = encrypter.encrypt(&key, &merged, &mut protected)?;

            if let None = merged.claim("kid") {
                if let Some(key_id) = encrypter.key_id() {
                    protected.set_key_id(key_id);
                }
            }
            protected.set_algorithm(encrypter.algorithm().name());

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
        input: impl AsRef<[u8]>,
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
        input: impl AsRef<[u8]>,
        selector: F,
    ) -> Result<(Vec<u8>, JweHeader), JoseError>
    where
        F: Fn(&JweHeader) -> Result<Option<&'a dyn JweDecrypter>, JoseError>,
    {
        (|| -> anyhow::Result<(Vec<u8>, JweHeader)> {
            let input = input.as_ref();
            let indexies: Vec<usize> = input
                .iter()
                .enumerate()
                .filter(|(_, b)| **b == b'.' as u8)
                .map(|(pos, _)| pos)
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

            match merged.claim("alg") {
                Some(Value::String(val)) => {
                    let expected_alg = decrypter.algorithm().name();
                    if val != expected_alg {
                        bail!("The JWE alg header claim is not {}: {}", expected_alg, val);
                    }
                }
                Some(_) => bail!("A alg header claim must be a string."),
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

            let key = decrypter.decrypt(encrypted_key, cencryption.key_len(), &merged)?;
            if key.len() != cencryption.key_len() {
                bail!("The key size is expected to be {}: {}", cencryption.key_len(), key.len());
            }

            let content = cencryption.decrypt(&key, iv, &ciphertext, header_b64, tag)?;
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
        input: impl AsRef<[u8]>,
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
        input: impl AsRef<[u8]>,
        selector: F,
    ) -> Result<(Vec<u8>, JweHeader), JoseError>
    where
        F: Fn(&JweHeader) -> Result<Option<&'a dyn JweDecrypter>, JoseError>,
    {
        (|| -> anyhow::Result<(Vec<u8>, JweHeader)> {
            let input = input.as_ref();
            let mut map: Map<String, Value> = serde_json::from_slice(input)?;

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

                let key = decrypter.decrypt(encrypted_key, cencryption.key_len(), &merged)?;
                if key.len() != cencryption.key_len() {
                    bail!("The key size is expected to be {}: {}", cencryption.key_len(), key.len());
                }
                
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

pub mod alg;

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::fmt::Display;

use anyhow::bail;
use once_cell::sync::Lazy;
use serde_json::{Map, Value};

use crate::jose::{JoseError, JoseHeader};
use crate::jwk::Jwk;
use crate::util::{self, SourceValue};

pub use crate::jws::alg::hmac::HmacJwsAlgorithm::HS256;
pub use crate::jws::alg::hmac::HmacJwsAlgorithm::HS384;
pub use crate::jws::alg::hmac::HmacJwsAlgorithm::HS512;

pub use crate::jws::alg::rsa::RsaJwsAlgorithm::RS256;
pub use crate::jws::alg::rsa::RsaJwsAlgorithm::RS384;
pub use crate::jws::alg::rsa::RsaJwsAlgorithm::RS512;

pub use crate::jws::alg::rsapss::RsaPssJwsAlgorithm::PS256;
pub use crate::jws::alg::rsapss::RsaPssJwsAlgorithm::PS384;
pub use crate::jws::alg::rsapss::RsaPssJwsAlgorithm::PS512;

pub use crate::jws::alg::ecdsa::EcdsaJwsAlgorithm::ES256;
pub use crate::jws::alg::ecdsa::EcdsaJwsAlgorithm::ES256K;
pub use crate::jws::alg::ecdsa::EcdsaJwsAlgorithm::ES384;
pub use crate::jws::alg::ecdsa::EcdsaJwsAlgorithm::ES512;

pub use crate::jws::alg::eddsa::EddsaJwsAlgorithm::EdDSA;

static DEFAULT_CONTEXT: Lazy<JwsContext> = Lazy::new(|| JwsContext::new());

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct JwsContext {
    acceptable_criticals: BTreeSet<String>,
}

impl JwsContext {
    pub fn new() -> Self {
        Self {
            acceptable_criticals: BTreeSet::new(),
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

    /// Return a representation of the data that is formatted by compact serialization.
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload data.
    /// * `header` - The JWS heaser claims.
    /// * `signer` - The JWS signer.
    pub fn serialize_compact(
        &self,
        payload: &[u8],
        header: &JwsHeader,
        signer: &dyn JwsSigner,
    ) -> Result<String, JoseError> {
        self.serialize_compact_with_selector(payload, header, |_header| Some(signer))
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
        header: &JwsHeader,
        selector: F,
    ) -> Result<String, JoseError>
    where
        F: Fn(&JwsHeader) -> Option<&'a dyn JwsSigner>,
    {
        (|| -> anyhow::Result<String> {
            let mut b64 = true;
            if let Some(vals) = header.critical() {
                if vals.iter().any(|e| e == "b64") {
                    if let Some(val) = header.base64url_encode_payload() {
                        b64 = *val;
                    }
                }
            }

            let signer = match selector(header) {
                Some(val) => val,
                None => bail!("A signer is not found."),
            };

            let mut header = header.claims_set().clone();
            header.insert(
                "alg".to_string(),
                Value::String(signer.algorithm().name().to_string()),
            );
            if let Some(key_id) = signer.key_id() {
                header.insert("kid".to_string(), Value::String(key_id.to_string()));
            }
            let header_bytes = serde_json::to_vec(&header)?;

            let mut capacity = 2;
            capacity += util::ceiling(header_bytes.len() * 4, 3);
            capacity += if b64 {
                util::ceiling(payload.len() * 4, 3)
            } else {
                payload.len()
            };
            capacity += util::ceiling(signer.signature_len() * 4, 3);

            let mut message = String::with_capacity(capacity);
            base64::encode_config_buf(header_bytes, base64::URL_SAFE_NO_PAD, &mut message);
            message.push_str(".");
            if b64 {
                base64::encode_config_buf(payload, base64::URL_SAFE_NO_PAD, &mut message);
            } else {
                let payload = std::str::from_utf8(payload)?;
                if payload.contains(".") {
                    bail!("A JWS payload cannot contain dot.");
                }
                message.push_str(payload);
            }

            let signature = signer.sign(message.as_bytes())?;

            message.push_str(".");
            base64::encode_config_buf(signature, base64::URL_SAFE_NO_PAD, &mut message);

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
    /// * `protected` - The JWS protected header claims.
    /// * `header` - The JWS unprotected header claims.
    /// * `payload` - The payload data.
    /// * `signer` - The JWS signer.
    pub fn serialize_general_json(
        &self,
        payload: &[u8],
        signer: &JwsMultiSigner,
    ) -> Result<String, JoseError> {
        (|| -> anyhow::Result<String> {
            let payload_b64 = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);

            let mut json = String::new();
            json.push_str("{\"signatures\":[");

            for (i, (protected, header, signer)) in signer.signers.iter().enumerate() {
                if i > 0 {
                    json.push_str(",");
                }

                let mut protected = match protected {
                    Some(val) => val.claims_set().clone(),
                    None => Map::new(),
                };
                protected.insert(
                    "alg".to_string(),
                    Value::String(signer.algorithm().name().to_string()),
                );

                let protected_bytes = serde_json::to_vec(&protected)?;
                let protected_b64 = base64::encode_config(&protected_bytes, base64::URL_SAFE_NO_PAD);

                let message = format!("{}.{}", &protected_b64, &payload_b64);
                let signature = signer.sign(message.as_bytes())?;

                json.push_str("{\"protected\":\"");
                json.push_str(&protected_b64);
                json.push_str("\"");

                if let Some(val) = header {
                    let header = serde_json::to_string(val.claims_set())?;
                    json.push_str(",\"header\":");
                    json.push_str(&header);
                }

                json.push_str(",\"signature\":\"");
                base64::encode_config_buf(&signature, base64::URL_SAFE_NO_PAD, &mut json);
                json.push_str("\"}");
            }

            json.push_str("],\"payload\":\"");
            json.push_str(&payload_b64);
            json.push_str("\"}");

            Ok(json)
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
    /// * `payload` - The payload data.
    /// * `protected` - The JWS protected header claims.
    /// * `header` - The JWS unprotected header claims.
    /// * `signer` - The JWS signer.
    pub fn serialize_flattened_json(
        &self,
        payload: &[u8],
        protected: Option<&JwsHeader>,
        header: Option<&JwsHeader>,
        signer: &dyn JwsSigner,
    ) -> Result<String, JoseError> {
        self.serialize_flattened_json_with_selector(payload, protected, header, |_header| {
            Some(signer)
        })
    }

    /// Return a representation of the data that is formatted by flatted json serialization.
    ///
    /// # Arguments
    ///
    /// * `payload` - The payload data.
    /// * `protected` - The JWS protected header claims.
    /// * `header` - The JWS unprotected header claims.
    /// * `selector` - a function for selecting the signing algorithm.
    pub fn serialize_flattened_json_with_selector<'a, F>(
        &self,
        payload: &[u8],
        protected: Option<&JwsHeader>,
        header: Option<&JwsHeader>,
        selector: F,
    ) -> Result<String, JoseError>
    where
        F: Fn(&JwsHeader) -> Option<&'a dyn JwsSigner>,
    {
        (|| -> anyhow::Result<String> {
            let mut b64 = true;

            let mut protected_map = if let Some(val) = protected {
                if let Some(vals) = val.critical() {
                    if vals.iter().any(|e| e == "b64") {
                        if let Some(val) = val.base64url_encode_payload() {
                            b64 = *val;
                        }
                    }
                }

                val.claims_set().clone()
            } else {
                Map::new()
            };

            if let Some(val) = header {
                for key in val.claims_set().keys() {
                    if protected_map.contains_key(key) {
                        bail!("Duplicate key exists: {}", key);
                    }
                }
            }

            let combined = JwsHeader::from_map(protected_map.clone())?;
            let signer = match selector(&combined) {
                Some(val) => val,
                None => bail!("A signer is not found."),
            };

            protected_map.insert(
                "alg".to_string(),
                Value::String(signer.algorithm().name().to_string()),
            );
            if let Some(key_id) = signer.key_id() {
                protected_map.insert("kid".to_string(), Value::String(key_id.to_string()));
            }

            let protected_json = serde_json::to_string(&protected_map)?;
            let protected_b64 = base64::encode_config(protected_json, base64::URL_SAFE_NO_PAD);

            let payload_b64;
            let payload = if b64 {
                payload_b64 = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);
                &payload_b64
            } else {
                std::str::from_utf8(payload)?
            };

            let message = format!("{}.{}", &protected_b64, payload);
            let signature = signer.sign(message.as_bytes())?;

            let mut json = String::new();
            json.push_str("{\"protected\":\"");
            json.push_str(&protected_b64);
            json.push_str("\"");

            if let Some(val) = &header {
                let header = serde_json::to_string(val.claims_set())?;
                json.push_str(",\"header\":");
                json.push_str(&header);
            }

            json.push_str(",\"payload\":\"");
            json.push_str(&payload);
            json.push_str("\"");

            json.push_str(",\"signature\":\"");
            base64::encode_config_buf(&signature, base64::URL_SAFE_NO_PAD, &mut json);
            json.push_str("\"}");

            Ok(json)
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
    /// * `header` - The decoded JWS header claims.
    /// * `verifier` - The JWS verifier.
    pub fn deserialize_compact(
        &self,
        input: &str,
        verifier: &dyn JwsVerifier,
    ) -> Result<(Vec<u8>, JwsHeader), JoseError> {
        self.deserialize_compact_with_selector(input, |_header| Ok(Some(verifier)))
    }

    /// Deserialize the input that is formatted by compact serialization.
    ///
    /// # Arguments
    ///
    /// * `input` - The input data.
    /// * `header` - The decoded JWS header claims.
    /// * `selector` - a function for selecting the verifying algorithm.
    pub fn deserialize_compact_with_selector<'a, F>(
        &self,
        input: &str,
        selector: F,
    ) -> Result<(Vec<u8>, JwsHeader), JoseError>
    where
        F: Fn(&JwsHeader) -> Result<Option<&'a dyn JwsVerifier>, JoseError>,
    {
        (|| -> anyhow::Result<(Vec<u8>, JwsHeader)> {
            let indexies: Vec<usize> = input
                .char_indices()
                .filter(|(_, c)| c == &'.')
                .map(|(i, _)| i)
                .collect();
            if indexies.len() != 2 {
                bail!(
                    "The compact serialization form of JWS must be three parts separated by colon."
                );
            }

            let header = &input[0..indexies[0]];
            let payload = &input[(indexies[0] + 1)..(indexies[1])];
            let signature = &input[(indexies[1] + 1)..];

            let header = base64::decode_config(header, base64::URL_SAFE_NO_PAD)?;
            let header: Map<String, Value> = serde_json::from_slice(&header)?;
            let header = JwsHeader::from_map(header)?;

            let verifier = match selector(&header)? {
                Some(val) => val,
                None => bail!("A verifier is not found."),
            };

            match header.algorithm() {
                Some(val) => {
                    let expected_alg = verifier.algorithm().name();
                    if val != expected_alg {
                        bail!("The JWS alg header claim is not {}: {}", expected_alg, val);
                    }
                }
                None => bail!("The JWS alg header claim is required."),
            }

            match verifier.key_id() {
                Some(expected) => match header.key_id() {
                    Some(actual) if expected == actual => {}
                    Some(actual) => bail!("The JWS kid header claim is mismatched: {}", actual),
                    None => bail!("The JWS kid header claim is required."),
                },
                None => {}
            }

            let mut b64 = true;
            if let Some(critical) = header.critical() {
                for name in critical {
                    if !self.is_acceptable_critical(name) {
                        bail!("The critical name '{}' is not supported.", name);
                    }

                    if name == "b64" {
                        if let Some(val) = header.base64url_encode_payload() {
                            b64 = *val;
                        }
                    }
                }
            }

            let message = &input[..(indexies[1])];
            let signature = base64::decode_config(signature, base64::URL_SAFE_NO_PAD)?;
            verifier.verify(message.as_bytes(), &signature)?;

            let payload = if b64 {
                base64::decode_config(payload, base64::URL_SAFE_NO_PAD)?
            } else {
                payload.to_string().into_bytes()
            };

            Ok((payload, header))
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err),
        })
    }

    /// Deserialize the input that is formatted by json serialization.
    ///
    /// # Arguments
    ///
    /// * `input` - The input data.
    /// * `header` - The decoded JWS header claims.
    /// * `verifier` - The JWS verifier.
    pub fn deserialize_json<'a>(
        &self,
        input: &str,
        verifier: &'a dyn JwsVerifier,
    ) -> Result<(Vec<u8>, JwsHeader), JoseError> {
        self.deserialize_json_with_selector(input, |header| {
            match header.algorithm() {
                Some(val) => {
                    let expected_alg = verifier.algorithm().name();
                    if val != expected_alg {
                        return Ok(None);
                    }
                }
                _ => return Ok(None),
            }

            match verifier.key_id() {
                Some(expected) => match header.key_id() {
                    Some(actual) if expected == actual => {}
                    _ => return Ok(None),
                },
                None => {}
            }

            Ok(Some(verifier))
        })
    }

    /// Deserialize the input that is formatted by json serialization.
    ///
    /// # Arguments
    ///
    /// * `input` - The input data.
    /// * `header` - The decoded JWS header claims.
    /// * `selector` - a function for selecting the verifying algorithm.
    pub fn deserialize_json_with_selector<'a, F>(
        &self,
        input: &str,
        selector: F,
    ) -> Result<(Vec<u8>, JwsHeader), JoseError>
    where
        F: Fn(&JwsHeader) -> Result<Option<&'a dyn JwsVerifier>, JoseError>,
    {
        (|| -> anyhow::Result<(Vec<u8>, JwsHeader)> {
            let mut map: Map<String, Value> = serde_json::from_str(input)?;

            let payload_base64 = match map.remove("payload") {
                Some(Value::String(val)) => val,
                Some(_) => bail!("The payload field must be string."),
                None => bail!("The payload field is required."),
            };

            let signatures = match map.remove("signatures") {
                Some(Value::Array(vals)) => {
                    let mut vec = Vec::with_capacity(vals.len());
                    for val in vals {
                        if let Value::Object(val) = val {
                            vec.push(val);
                        } else {
                            bail!("The signatures field must be a array of object.");
                        }
                    }
                    vec
                }
                Some(_) => bail!("The signatures field must be a array."),
                None => {
                    let mut vec = Vec::with_capacity(1);
                    vec.push(map);
                    vec
                }
            };

            for mut sig in signatures {
                let header = sig.remove("header");

                let protected_base64 = match sig.get("protected") {
                    Some(Value::String(val)) => val,
                    Some(_) => bail!("The protected field must be a string."),
                    None => bail!("The JWS alg header claim must be in protected."),
                };

                let protected = base64::decode_config(protected_base64, base64::URL_SAFE_NO_PAD)?;
                let protected: Map<String, Value> = serde_json::from_slice(&protected)?;
                if let None = protected.get("alg") {
                    bail!("The JWS alg header claim must be in protected.");
                }

                let header = match header {
                    Some(Value::Object(mut val)) => {
                        for (key, value) in &protected {
                            if val.contains_key(key) {
                                bail!("Duplicate key exists: {}", key);
                            } else {
                                val.insert(key.clone(), value.clone());
                            }
                        }
                        val
                    }
                    Some(_) => bail!("The protected field must be a object."),
                    None => protected.clone(),
                };

                let signature_base64 = match sig.get("signature") {
                    Some(Value::String(val)) => val,
                    Some(_) => bail!("The signature field must be string."),
                    None => bail!("The signature field is required."),
                };

                let header = JwsHeader::from_map(header)?;
                let verifier = match selector(&header)? {
                    Some(val) => val,
                    None => continue,
                };

                match header.claim("alg") {
                    Some(Value::String(val)) => {
                        let expected_alg = verifier.algorithm().name();
                        if val != expected_alg {
                            bail!("The JWS alg header claim is not {}: {}", expected_alg, val);
                        }
                    }
                    Some(_) => bail!("The JWS alg header claim must be a string."),
                    None => bail!("The JWS alg header claim is required."),
                }

                match header.algorithm() {
                    Some(val) => {
                        let expected_alg = verifier.algorithm().name();
                        if val != expected_alg {
                            bail!("The JWS alg header claim is not {}: {}", expected_alg, val);
                        }
                    }
                    None => bail!("The JWS alg header claim is required."),
                }

                match verifier.key_id() {
                    Some(expected) => match header.key_id() {
                        Some(actual) if expected == actual => {}
                        Some(actual) => bail!("The JWS kid header claim is mismatched: {}", actual),
                        None => bail!("The JWS kid header claim is required."),
                    },
                    None => {}
                }

                let mut b64 = true;
                if let Some(Value::Array(vals)) = protected.get("critical") {
                    for val in vals {
                        match val {
                            Value::String(name) => {
                                if !self.is_acceptable_critical(name) {
                                    bail!("The critical name '{}' is not supported.", name);
                                }

                                if name == "b64" {
                                    match protected.get("b64") {
                                        Some(Value::Bool(b64_val)) => {
                                            b64 = *b64_val;
                                        }
                                        Some(_) => bail!("The JWS b64 header claim must be bool."),
                                        None => {}
                                    }
                                }
                            }
                            _ => bail!("The JWS critical header claim must be a array of string."),
                        }
                    }
                }

                let message = format!("{}.{}", &protected_base64, &payload_base64);
                let signature = base64::decode_config(&signature_base64, base64::URL_SAFE_NO_PAD)?;
                verifier.verify(message.as_bytes(), &signature)?;

                let payload = if b64 {
                    base64::decode_config(&payload_base64, base64::URL_SAFE_NO_PAD)?
                } else {
                    payload_base64.into_bytes()
                };

                return Ok((payload, header));
            }

            bail!("A signature that matched the algorithm and key_id is not found.");
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
/// * `signer` - The JWS signer.
pub fn serialize_compact(
    payload: &[u8],
    header: &JwsHeader,
    signer: &dyn JwsSigner,
) -> Result<String, JoseError> {
    DEFAULT_CONTEXT.serialize_compact(payload, header, signer)
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
    header: &JwsHeader,
    selector: F,
) -> Result<String, JoseError>
where
    F: Fn(&JwsHeader) -> Option<&'a dyn JwsSigner>,
{
    DEFAULT_CONTEXT.serialize_compact_with_selector(payload, header, selector)
}

/// Return a representation of the data that is formatted by flattened json serialization.
///
/// # Arguments
///
/// * `protected` - The JWS protected header claims.
/// * `header` - The JWS unprotected header claims.
/// * `payload` - The payload data.
/// * `signer` - The JWS signer.
pub fn serialize_general_json(
    payload: &[u8],
    signer: &JwsMultiSigner,
) -> Result<String, JoseError> {
    DEFAULT_CONTEXT.serialize_general_json(payload, signer)
}

/// Return a representation of the data that is formatted by flattened json serialization.
///
/// # Arguments
///
/// * `payload` - The payload data.
/// * `protected` - The JWS protected header claims.
/// * `header` - The JWS unprotected header claims.
/// * `signer` - The JWS signer.
pub fn serialize_flattened_json(
    payload: &[u8],
    protected: Option<&JwsHeader>,
    header: Option<&JwsHeader>,
    signer: &dyn JwsSigner,
) -> Result<String, JoseError> {
    DEFAULT_CONTEXT.serialize_flattened_json(payload, protected, header, signer)
}

/// Return a representation of the data that is formatted by flatted json serialization.
///
/// # Arguments
///
/// * `payload` - The payload data.
/// * `protected` - The JWS protected header claims.
/// * `header` - The JWS unprotected header claims.
/// * `selector` - a function for selecting the signing algorithm.
pub fn serialize_flattened_json_with_selector<'a, F>(
    payload: &[u8],
    protected: Option<&JwsHeader>,
    header: Option<&JwsHeader>,
    selector: F,
) -> Result<String, JoseError>
where
    F: Fn(&JwsHeader) -> Option<&'a dyn JwsSigner>,
{
    DEFAULT_CONTEXT.serialize_flattened_json_with_selector(payload, protected, header, selector)
}

/// Deserialize the input that is formatted by compact serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `header` - The decoded JWS header claims.
/// * `verifier` - The JWS verifier.
pub fn deserialize_compact(
    input: &str,
    verifier: &dyn JwsVerifier,
) -> Result<(Vec<u8>, JwsHeader), JoseError> {
    DEFAULT_CONTEXT.deserialize_compact(input, verifier)
}

/// Deserialize the input that is formatted by compact serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `header` - The decoded JWS header claims.
/// * `selector` - a function for selecting the verifying algorithm.
pub fn deserialize_compact_with_selector<'a, F>(
    input: &str,
    selector: F,
) -> Result<(Vec<u8>, JwsHeader), JoseError>
where
    F: Fn(&JwsHeader) -> Result<Option<&'a dyn JwsVerifier>, JoseError>,
{
    DEFAULT_CONTEXT.deserialize_compact_with_selector(input, selector)
}

/// Deserialize the input that is formatted by json serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `header` - The decoded JWS header claims.
/// * `verifier` - The JWS verifier.
pub fn deserialize_json<'a>(
    input: &str,
    verifier: &'a dyn JwsVerifier,
) -> Result<(Vec<u8>, JwsHeader), JoseError> {
    DEFAULT_CONTEXT.deserialize_json(input, verifier)
}

/// Deserialize the input that is formatted by json serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `header` - The decoded JWS header claims.
/// * `selector` - a function for selecting the verifying algorithm.
pub fn deserialize_json_with_selector<'a, F>(
    input: &str,
    selector: F,
) -> Result<(Vec<u8>, JwsHeader), JoseError>
where
    F: Fn(&JwsHeader) -> Result<Option<&'a dyn JwsVerifier>, JoseError>,
{
    DEFAULT_CONTEXT.deserialize_json_with_selector(input, selector)
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct JwsHeader {
    claims: Map<String, Value>,
    sources: HashMap<String, SourceValue>,
}

impl JwsHeader {
    /// Return a JwsHeader instance.
    pub fn new() -> Self {
        Self {
            claims: Map::new(),
            sources: HashMap::new(),
        }
    }

    /// Set a value for algorithm header claim (alg).
    ///
    /// # Arguments
    ///
    /// * `value` - a algorithm
    pub fn set_algorithm(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("alg".to_string(), Value::String(value));
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

    /// Set a value for base64url-encode payload header claim (b64).
    ///
    /// # Arguments
    ///
    /// * `value` - is base64url-encode payload
    pub fn set_base64url_encode_payload(&mut self, value: bool) {
        self.claims.insert("b64".to_string(), Value::Bool(value));
    }

    /// Return the value for base64url-encode payload header claim (b64).
    pub fn base64url_encode_payload(&self) -> Option<&bool> {
        match self.claims.get("b64") {
            Some(Value::Bool(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for url header claim (url).
    ///
    /// # Arguments
    ///
    /// * `value` - a url
    pub fn set_url(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("url".to_string(), Value::String(value));
    }

    /// Return the value for url header claim (url).
    pub fn url(&self) -> Option<&str> {
        match self.claims.get("url") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for a nonce header claim (nonce).
    ///
    /// # Arguments
    ///
    /// * `value` - A nonce
    pub fn set_nonce(&mut self, value: Vec<u8>) {
        let key = "nonce".to_string();
        let val = base64::encode_config(&value, base64::URL_SAFE_NO_PAD);
        self.claims.insert(key.clone(), Value::String(val));
        self.sources.insert(key, SourceValue::Bytes(value));
    }

    /// Return the value for nonce header claim (nonce).
    pub fn nonce(&self) -> Option<&Vec<u8>> {
        match self.sources.get("nonce") {
            Some(SourceValue::Bytes(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }
}

impl JoseHeader for JwsHeader {
    fn from_map(claims: Map<String, Value>) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            if let Some(Value::Bool(false)) = claims.get("b64") {
                if let Some(Value::Array(vals)) = claims.get("crit") {
                    if !vals.iter().any(|e| e == "b64") {
                        bail!("The b64 header claim name must be in critical.");
                    }
                }
            }

            let mut sources = HashMap::new();
            for (key, value) in &claims {
                match key.as_ref() {
                    "alg" | "jku" | "x5u" | "kid" | "typ" | "cty" | "url" => match value {
                        Value::String(_) => {},
                        _ => bail!("The JWT {} header claim must be a string.", key),
                    },
                    "b64" => match value {
                        Value::Bool(_) => {},
                        _ => bail!("The JWT {} header claim must be a bool.", key),
                    },
                    "jwk" => match value {
                        Value::Object(vals) => {
                            let vals = Jwk::from_map(vals.clone())?;
                            sources.insert(key.clone(), SourceValue::Jwk(vals));
                        },
                        _ => bail!("The JWT {} header claim must be a string.", key),
                    },
                    "x5t" => match value {
                        Value::String(val) => {
                            let val = base64::decode_config(val, base64::URL_SAFE_NO_PAD)?;
                            sources.insert(key.clone(), SourceValue::Bytes(val));
                        },
                        _ => bail!("The JWT {} header claim must be a string.", key),
                    },
                    "x5t#S256" =>  match value {
                        Value::String(val) => {
                            let val = base64::decode_config(val, base64::URL_SAFE_NO_PAD)?;
                            sources.insert(key.clone(), SourceValue::Bytes(val));
                        },
                        _ => bail!("The JWT {} header claim must be a string.", key),
                    },
                    "x5c" => match value {
                        Value::Array(vals) => {
                            let mut vec = Vec::with_capacity(vals.len());
                            for val in vals {
                                match val {
                                    Value::String(val) => {
                                        let decoded = base64::decode_config(val, base64::URL_SAFE_NO_PAD)?;
                                        vec.push(decoded);
                                    },
                                    _ => bail!("An element of the JWT {} header claim must be a string.", key),
                                }
                            }
                            sources.insert(key.clone(), SourceValue::BytesArray(vec));
                        },
                        _ => bail!("The JWT {} header claim must be a array.", key),
                    },
                    "crit" => match value {
                        Value::Array(vals) => {
                            let mut vec = Vec::with_capacity(vals.len());
                            for val in vals {
                                match val {
                                    Value::String(val) => vec.push(val.to_string()),
                                    _ => bail!("An element of the JWT {} header claim must be a string.", key),
                                }
                            }
                            sources.insert(key.clone(), SourceValue::StringArray(vec));
                        },
                        _ => bail!("The JWT {} header claim must be a array.", key),
                    },
                    "nonce" => match value {
                        Value::String(val) => {
                            let val = base64::decode_config(val, base64::URL_SAFE_NO_PAD)?;
                            sources.insert(key.clone(), SourceValue::Bytes(val));
                        },
                        _ => bail!("The JWT {} header claim must be a string.", key),
                    },
                    _ => {},
                }
            }

            Ok(Self {
                claims,
                sources,
            })
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwsFormat(err)
        })
    }

    fn claims_set(&self) -> &Map<String, Value> {
        &self.claims
    }

    fn set_claim(&mut self, key: &str, value: Option<Value>) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            match key {
                "alg" | "jku" | "x5u" | "kid" | "typ" | "cty" | "url" => match &value {
                    Some(Value::String(_)) => {
                        self.claims.insert(key.to_string(), value.unwrap());
                    }
                    None => {
                        self.claims.remove(key);
                    }
                    _ => bail!("The JWS {} header claim must be string.", key),
                },
                "jwk" => match &value {
                    Some(Value::Object(vals)) => {
                        let key = key.to_string();
                        let val = Jwk::from_map(vals.clone())?;
                        self.claims.insert(key.clone(), value.unwrap());
                        self.sources.insert(key, SourceValue::Jwk(val));
                    }
                    None => {
                        self.claims.remove(key);
                        self.sources.remove(key);
                    }
                    _ => bail!("The JWS {} header claim must be a string.", key),
                },
                "x5t" => match &value {
                    Some(Value::String(val)) => {
                        let key = key.to_string();
                        let val = base64::decode_config(val, base64::URL_SAFE_NO_PAD)?;
                        self.claims.insert(key.clone(), value.unwrap());
                        self.sources.insert(key, SourceValue::Bytes(val));
                    }
                    None => {
                        self.claims.remove(key);
                        self.sources.remove(key);
                    }
                    _ => bail!("The JWS {} header claim must be a string.", key),
                },
                "x5t#S256" => match &value {
                    Some(Value::String(val)) => {
                        let key = key.to_string();
                        let val = base64::decode_config(val, base64::URL_SAFE_NO_PAD)?;
                        self.claims.insert(key.to_string(), value.unwrap());
                        self.sources.insert(key, SourceValue::Bytes(val));
                    }
                    None => {
                        self.claims.remove(key);
                        self.sources.remove(key);
                    }
                    _ => bail!("The JWS {} header claim must be a string.", key),
                },
                "x5c" => match &value {
                    Some(Value::Array(vals)) => {
                        let key = key.to_string();
                        let mut vec = Vec::with_capacity(vals.len());
                        for val in vals {
                            match val {
                                Value::String(val) => {
                                    let decoded =
                                        base64::decode_config(val, base64::URL_SAFE_NO_PAD)?;
                                    vec.push(decoded);
                                }
                                _ => bail!(
                                    "An element of the JWS {} header claim must be a string.",
                                    key
                                ),
                            }
                        }
                        self.claims.insert(key.clone(), value.unwrap());
                        self.sources.insert(key, SourceValue::BytesArray(vec));
                    }
                    None => {
                        self.claims.remove(key);
                        self.sources.remove(key);
                    }
                    _ => bail!("The JWS {} header claim must be a array.", key),
                },
                "crit" => match &value {
                    Some(Value::Array(vals)) => {
                        let key = key.to_string();
                        let mut vec = Vec::with_capacity(vals.len());
                        for val in vals {
                            match val {
                                Value::String(val) => vec.push(val.to_string()),
                                _ => bail!(
                                    "An element of the JWS {} header claim must be a string.",
                                    key
                                ),
                            }
                        }
                        self.claims.insert(key.to_string(), value.unwrap());
                        self.sources.insert(key, SourceValue::StringArray(vec));
                    }
                    None => {
                        self.claims.remove(key);
                        self.sources.remove(key);
                    }
                    _ => bail!("The JWS {} header claim must be a array.", key),
                },
                "nonce" => match &value {
                    Some(Value::String(val)) => {
                        let key = key.to_string();
                        let val = base64::decode_config(val, base64::URL_SAFE_NO_PAD)?;
                        self.claims.insert(key.clone(), value.unwrap());
                        self.sources.insert(key, SourceValue::Bytes(val));
                    }
                    None => {
                        self.claims.remove(key);
                        self.sources.remove(key);
                    }
                    _ => bail!("The JWS {} header claim must be a string.", key),
                },
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
        .map_err(|err| JoseError::InvalidJwsFormat(err))
    }
}

impl Into<Map<String, Value>> for JwsHeader {
    fn into(self) -> Map<String, Value> {
        self.claims
    }
}

impl Display for JwsHeader {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let val = serde_json::to_string(self.claims_set()).map_err(|_e| std::fmt::Error {})?;
        fmt.write_str(&val)
    }
}

pub trait JwsAlgorithm {
    /// Return the "alg" (algorithm) header parameter value of JWS.
    fn name(&self) -> &str;

    /// Return the "kty" (key type) header parameter value of JWK.
    fn key_type(&self) -> &str;
}

pub trait JwsSigner {
    /// Return the source algrithm instance.
    fn algorithm(&self) -> &dyn JwsAlgorithm;

    /// Return the signature length of JWS.
    fn signature_len(&self) -> usize;

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

    /// Return a signature of the data.
    ///
    /// # Arguments
    ///
    /// * `message` - The message data to sign.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError>;
}

pub struct JwsMultiSigner<'a> {
    signers: Vec<(
        Option<&'a JwsHeader>,
        Option<&'a JwsHeader>,
        &'a dyn JwsSigner,
    )>,
}

impl<'a> JwsMultiSigner<'a> {
    pub fn new() -> Self {
        JwsMultiSigner {
            signers: Vec::new(),
        }
    }

    pub fn add_signer(
        &mut self,
        protected: Option<&'a JwsHeader>,
        header: Option<&'a JwsHeader>,
        signer: &'a dyn JwsSigner,
    ) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            if let Some(protected) = protected {
                if let Some(header) = header {
                    let protected_map = protected.claims_set();
                    let header_map = header.claims_set();
                    for key in header_map.keys() {
                        if protected_map.contains_key(key) {
                            bail!("Duplicate key exists: {}", key);
                        }
                    }
                }
            }

            self.signers.push((protected, header, signer));

            Ok(())
        })()
        .map_err(|err| JoseError::InvalidJwsFormat(err))
    }
}

pub trait JwsVerifier {
    /// Return the source algrithm instance.
    fn algorithm(&self) -> &dyn JwsAlgorithm;

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

    /// Verify the data by the signature.
    ///
    /// # Arguments
    ///
    /// * `message` - a message data to verify.
    /// * `signature` - a signature data.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError>;
}

#[cfg(test)]
mod tests {
    use crate::jws::{self, EdDSA, JwsHeader, JwsMultiSigner, ES256, RS256};
    use crate::prelude::*;
    use anyhow::Result;
    use serde_json::Value;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;

    #[test]
    fn test_jws_compact_serialization() -> Result<()> {
        let alg = RS256;

        let private_key = load_file("pem/RSA_2048bit_pkcs8_private.pem")?;
        let public_key = load_file("pem/RSA_2048bit_pkcs8_public.pem")?;

        let mut src_header = JwsHeader::new();
        src_header.set_token_type("JWT");
        let src_payload = b"test payload!";
        let signer = alg.signer_from_pem(&private_key)?;
        let jwt = jws::serialize_compact(src_payload, &src_header, &signer)?;

        let verifier = alg.verifier_from_pem(&public_key)?;
        let (dst_payload, dst_header) = jws::deserialize_compact(&jwt, &verifier)?;

        src_header.set_claim("alg", Some(Value::String(alg.name().to_string())))?;
        assert_eq!(src_header, dst_header);
        assert_eq!(src_payload.to_vec(), dst_payload);

        Ok(())
    }

    #[test]
    fn test_jws_json_serialization() -> Result<()> {
        let alg = RS256;

        let private_key = load_file("pem/RSA_2048bit_pkcs8_private.pem")?;
        let public_key = load_file("pem/RSA_2048bit_pkcs8_public.pem")?;

        let src_payload = b"test payload!";
        let mut src_protected = JwsHeader::new();
        src_protected.set_key_id("xxx");
        let mut src_header = JwsHeader::new();
        src_header.set_token_type("JWT");
        let signer = alg.signer_from_pem(&private_key)?;
        let jwt = jws::serialize_flattened_json(
            src_payload,
            Some(&src_protected),
            Some(&src_header),
            &signer,
        )?;

        let verifier = alg.verifier_from_pem(&public_key)?;
        let (dst_payload, dst_header) = jws::deserialize_json(&jwt, &verifier)?;

        src_header.set_claim("alg", Some(Value::String(alg.name().to_string())))?;
        assert_eq!(src_protected.key_id(), dst_header.key_id());
        assert_eq!(src_header.token_type(), dst_header.token_type());
        assert_eq!(src_payload.to_vec(), dst_payload);

        Ok(())
    }

    #[test]
    fn test_jws_general_json_serialization() -> Result<()> {
        let private_key_1 = load_file("pem/RSA_2048bit_pkcs8_private.pem")?;
        let private_key_2 = load_file("pem/ECDSA_P-256_pkcs8_private.pem")?;
        let private_key_3 = load_file("pem/ED25519_pkcs8_private.pem")?;

        let public_key = load_file("pem/ECDSA_P-256_pkcs8_public.pem")?;

        let src_payload = b"test payload!";

        let mut src_protected_1 = JwsHeader::new();
        src_protected_1.set_key_id("xxx-1");
        let mut src_header_1 = JwsHeader::new();
        src_header_1.set_token_type("JWT-1");
        let signer_1 = RS256.signer_from_pem(&private_key_1)?;

        let mut src_protected_2 = JwsHeader::new();
        src_protected_2.set_key_id("xxx-2");
        let mut src_header_2 = JwsHeader::new();
        src_header_2.set_token_type("JWT-2");
        let signer_2 = ES256.signer_from_pem(&private_key_2)?;

        let mut src_protected_3 = JwsHeader::new();
        src_protected_3.set_key_id("xxx-3");
        let mut src_header_3 = JwsHeader::new();
        src_header_3.set_token_type("JWT-3");
        let signer_3 = EdDSA.signer_from_pem(&private_key_3)?;

        let mut multi_signer = JwsMultiSigner::new();
        multi_signer.add_signer(Some(&src_protected_1), Some(&src_header_1), &signer_1)?;
        multi_signer.add_signer(Some(&src_protected_2), Some(&src_header_2), &signer_2)?;
        multi_signer.add_signer(Some(&src_protected_3), Some(&src_header_3), &signer_3)?;

        let json = jws::serialize_general_json(src_payload, &multi_signer)?;

        let verifier = ES256.verifier_from_pem(&public_key)?;
        let (dst_payload, dst_header) = jws::deserialize_json(&json, &verifier)?;

        assert_eq!(dst_header.algorithm(), Some("ES256"));
        assert_eq!(src_protected_2.key_id(), dst_header.key_id());
        assert_eq!(src_header_2.token_type(), dst_header.token_type());
        assert_eq!(src_payload.to_vec(), dst_payload);

        Ok(())
    }

    fn load_file(path: &str) -> Result<Vec<u8>> {
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push("data");
        pb.push(path);

        let mut file = File::open(&pb)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(data)
    }
}

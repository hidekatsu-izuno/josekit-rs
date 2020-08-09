pub mod alg;
mod multi_signer;
mod multi_verifier;

use std::collections::HashMap;
use std::fmt::Display;

use anyhow::bail;
use serde_json::{Map, Value};

use crate::jose::{JoseError, JoseHeader};
use crate::jwk::Jwk;
use crate::util::SourceValue;

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

pub use crate::jws::alg::eddsa::EddsaJwsAlgorithm::EDDSA;

pub use crate::jws::multi_signer::JwsMultiSigner;
pub use crate::jws::multi_verifier::JwsMultiVerifier;

/// Represents plain JWS object with header and payload.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Jws;

impl Jws {
    /// Return a representation of the data that is formatted by compact serialization.
    ///
    /// # Arguments
    /// * `header` - The JWS heaser claims.
    /// * `payload` - The payload data.
    /// * `signer` - The JWS signer.
    pub fn serialize_compact(
        header: &JwsHeader,
        payload: &[u8],
        signer: &dyn JwsSigner,
    ) -> Result<String, JoseError> {
        Self::serialize_compact_with_selector(header, payload, |_header| Some(Box::new(signer)))
    }

    /// Return a representation of the data that is formatted by compact serialization.
    ///
    /// # Arguments
    /// * `header` - The JWS heaser claims.
    /// * `payload` - The payload data.
    /// * `selector` - a function for selecting the signing algorithm.
    pub fn serialize_compact_with_selector<'a, F>(
        header: &JwsHeader,
        payload: &[u8],
        selector: F,
    ) -> Result<String, JoseError>
    where
        F: FnOnce(&JwsHeader) -> Option<Box<&'a dyn JwsSigner>>,
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
            let header = serde_json::to_string(&header)?;
            let header = base64::encode_config(header, base64::URL_SAFE_NO_PAD);

            let payload_base64;
            let payload = if b64 {
                payload_base64 = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);
                &payload_base64
            } else {
                match std::str::from_utf8(payload) {
                    Ok(val) => {
                        if val.contains(".") {
                            bail!("A JWS payload cannot contain dot.");
                        }
                        val
                    }
                    Err(err) => bail!("{}", err),
                }
            };

            let mut message = String::with_capacity(
                header.len() + payload.len() + signer.algorithm().signature_len() + 2,
            );

            message.push_str(&header);
            message.push_str(".");
            message.push_str(&payload);

            let signature = signer.sign(message.as_bytes())?;

            let signature = base64::encode_config(signature, base64::URL_SAFE_NO_PAD);
            message.push_str(".");
            message.push_str(&signature);

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
    /// * `protected` - The JWS protected header claims.
    /// * `header` - The JWS unprotected header claims.
    /// * `payload` - The payload data.
    /// * `signer` - The JWS signer.
    pub fn serialize_flattened_json(
        protected: Option<&JwsHeader>,
        header: Option<&JwsHeader>,
        payload: &[u8],
        signer: &dyn JwsSigner,
    ) -> Result<String, JoseError> {
        Self::serialize_flattened_json_with_selector(
            protected, 
            header, 
            payload, 
            |_header| Some(Box::new(signer))
        )
    }

    /// Return a representation of the data that is formatted by flatted json serialization.
    ///
    /// # Arguments
    /// * `protected` - The JWS protected header claims.
    /// * `header` - The JWS unprotected header claims.
    /// * `payload` - The payload data.
    /// * `selector` - a function for selecting the signing algorithm.
    pub fn serialize_flattened_json_with_selector<'a, F>(
        protected: Option<&JwsHeader>,
        header: Option<&JwsHeader>,
        payload: &[u8],
        selector: F,
    ) -> Result<String, JoseError>
    where
        F: FnOnce(&JwsHeader) -> Option<Box<&'a dyn JwsSigner>>,
    {
        (|| -> anyhow::Result<String> {
            let mut result = Map::new();
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
            let protected_base64 = base64::encode_config(protected_json, base64::URL_SAFE_NO_PAD);

            let payload_base64;
            let payload = if b64 {
                payload_base64 = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);
                &payload_base64
            } else {
                match std::str::from_utf8(payload) {
                    Ok(val) => val,
                    Err(err) => bail!("{}", err),
                }
            };

            let message = format!("{}.{}", &protected_base64, payload);

            result.insert("protected".to_string(), Value::String(protected_base64));

            if let Some(val) = &header {
                result.insert(
                    "header".to_string(),
                    Value::Object(val.claims_set().clone()),
                );
            }

            result.insert("payload".to_string(), Value::String(payload.to_string()));

            let signature = signer.sign(message.as_bytes())?;
            let signature = base64::encode_config(&signature, base64::URL_SAFE_NO_PAD);
            result.insert("signature".to_string(), Value::String(signature));

            let result_json = serde_json::to_string(&result)?;
            Ok(result_json)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err),
        })
    }

    /// Deserialize the input that is formatted by compact serialization.
    ///
    /// # Arguments
    /// * `input` - The input data.
    /// * `header` - The decoded JWS header claims.
    /// * `verifier` - The JWS verifier.
    pub fn deserialize_compact(
        input: &str,
        verifier: &dyn JwsVerifier,
    ) -> Result<(JwsHeader, Vec<u8>), JoseError> {
        Self::deserialize_compact_with_selector(input, |_header| Ok(Box::new(verifier)))
    }

    /// Deserialize the input that is formatted by compact serialization.
    ///
    /// # Arguments
    /// * `input` - The input data.
    /// * `header` - The decoded JWS header claims.
    /// * `selector` - a function for selecting the verifying algorithm.
    pub fn deserialize_compact_with_selector<'a, F>(
        input: &str,
        selector: F,
    ) -> Result<(JwsHeader, Vec<u8>), JoseError>
    where
        F: FnOnce(&JwsHeader) -> Result<Box<&'a dyn JwsVerifier>, JoseError>,
    {
        (|| -> anyhow::Result<(JwsHeader, Vec<u8>)> {
            let indexies: Vec<usize> = input
                .char_indices()
                .filter(|(_, c)| c == &'.')
                .map(|(i, _)| i)
                .collect();
            if indexies.len() != 2 {
                bail!("The signed token must be three parts separated by colon.");
            }

            let header = &input[0..indexies[0]];
            let header = base64::decode_config(header, base64::URL_SAFE_NO_PAD)?;
            let header: Map<String, Value> = serde_json::from_slice(&header)?;
            let header = JwsHeader::from_map(header)?;

            let verifier = selector(&header)?;

            let expected_alg = verifier.algorithm().name();
            match header.claim("alg") {
                Some(Value::String(val)) if val == expected_alg => {}
                Some(Value::String(val)) => {
                    bail!("The JWS alg header claim is not {}: {}", expected_alg, val)
                }
                Some(_) => bail!("The JWS alg header claim must be a string."),
                None => bail!("The JWS alg header claim is required."),
            }

            let expected_kid = verifier.key_id();
            match (expected_kid, header.claim("kid")) {
                (Some(expected), Some(actual)) if expected == actual => {}
                (None, None) => {}
                (Some(_), Some(actual)) => {
                    bail!("The JWS kid header claim is mismatched: {}", actual)
                }
                _ => bail!("The JWS kid header claim is missing."),
            }

            if let Some(critical) = header.critical() {
                for name in critical {
                    if !verifier.is_acceptable_critical(name) {
                        bail!("The critical name '{}' is not supported.", name);
                    }
                }
            }

            let mut b64 = true;
            if let Some(vals) = header.critical() {
                if vals.iter().any(|e| e == "b64") {
                    if let Some(val) = header.base64url_encode_payload() {
                        b64 = *val;
                    }
                }
            }

            let payload = &input[(indexies[0] + 1)..(indexies[1])];
            let payload = if b64 {
                base64::decode_config(payload, base64::URL_SAFE_NO_PAD)?
            } else {
                payload.as_bytes().to_vec()
            };

            let signature = &input[(indexies[1] + 1)..];
            let signature = base64::decode_config(signature, base64::URL_SAFE_NO_PAD)?;

            let message = &input[..(indexies[1])];
            verifier.verify(message.as_bytes(), &signature)?;

            Ok((header, payload))
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err),
        })
    }

    /// Deserialize the input that is formatted by flattened json serialization.
    ///
    /// # Arguments
    /// * `input` - The input data.
    /// * `header` - The decoded JWS header claims.
    /// * `verifier` - The JWS verifier.
    pub fn deserialize_flattened_json<'a>(
        input: &str,
        verifier: &'a dyn JwsVerifier,
    ) -> Result<(JwsHeader, Vec<u8>), JoseError> {
        Self::deserialize_flattened_json_with_selector(input, |_header| Ok(Box::new(verifier)))
    }

    /// Deserialize the input that is formatted by flattened json serialization.
    ///
    /// # Arguments
    /// * `input` - The input data.
    /// * `header` - The decoded JWS header claims.
    /// * `selector` - a function for selecting the verifying algorithm.
    pub fn deserialize_flattened_json_with_selector<'a, F>(
        input: &str,
        selector: F,
    ) -> Result<(JwsHeader, Vec<u8>), JoseError>
    where
        F: FnOnce(&JwsHeader) -> Result<Box<&'a dyn JwsVerifier>, JoseError>,
    {
        (|| -> anyhow::Result<(JwsHeader, Vec<u8>)> {
            let mut map: Map<String, Value> = serde_json::from_str(input)?;

            let protected = match map.remove("protected") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("The protected field must be a string."),
                None => bail!("The JWS alg header claim must be in protected."),
            };

            let mut header: Map<String, Value> = serde_json::from_slice(&protected)?;
            if let None = header.get("alg") {
                bail!("The JWS alg header claim must be in protected.");
            }

            match map.remove("header") {
                Some(Value::Object(val)) => {
                    for key in val.keys() {
                        if header.contains_key(key) {
                            bail!("Duplicate key exists: {}", key);
                        }
                    }
                    header.extend(val);
                }
                Some(_) => bail!("The header field must be a object."),
                None => {}
            }

            let header = JwsHeader::from_map(header)?;
            let verifier = selector(&header)?;

            let expected_kid = verifier.key_id();
            match (expected_kid, header.claim("kid")) {
                (Some(expected), Some(actual)) if expected == actual => {}
                (None, None) => {}
                (Some(_), Some(actual)) => {
                    bail!("The JWS kid header claim is mismatched: {}", actual);
                }
                _ => bail!("The JWS kid header claim is missing."),
            }

            if let Some(critical) = header.critical() {
                for name in critical {
                    if !verifier.is_acceptable_critical(name) {
                        bail!("The critical name '{}' is not supported.", name);
                    }
                }
            }

            let mut b64 = true;
            if let Some(vals) = header.critical() {
                if vals.iter().any(|e| e == "b64") {
                    if let Some(val) = header.base64url_encode_payload() {
                        b64 = *val;
                    }
                }
            }

            let payload = match map.remove("payload") {
                Some(Value::String(val)) => {
                    if b64 {
                        base64::decode_config(val, base64::URL_SAFE_NO_PAD)?
                    } else {
                        val.into_bytes()
                    }
                }
                Some(_) => bail!("The payload field must be string."),
                None => bail!("The payload field is required."),
            };

            let signature = match map.remove("signature") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("The signature field must be string."),
                None => bail!("The signature field is required."),
            };

            let mut message = protected;
            message.extend(b".");
            message.extend(&payload);

            verifier.verify(&message, &signature)?;

            Ok((header, payload))
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err),
        })
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct JwsHeader {
    claims: Map<String, Value>,
    sources: HashMap<String, SourceValue>,
}

impl JwsHeader {
    pub fn new() -> Self {
        Self {
            claims: Map::new(),
            sources: HashMap::new(),
        }
    }

    /// Set a value for JWK set URL header claim (jku).
    ///
    /// # Arguments
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
                                    "An element of the JWT {} header claim must be a string.",
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
        .map_err(|err| JoseError::InvalidJwtFormat(err))
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

    /// Return the "kty" (key type) header parameter value of JWS.
    fn key_type(&self) -> &str;

    /// Return the signature length of JWS.
    fn signature_len(&self) -> usize;
}

pub trait JwsSigner {
    /// Return the source algrithm instance.
    fn algorithm(&self) -> &dyn JwsAlgorithm;

    /// Return the source key ID.
    /// The default value is a value of kid parameter in JWK.
    fn key_id(&self) -> Option<&str>;

    /// Set a compared value for a kid header claim (kid).
    ///
    /// # Arguments
    /// * `key_id` - a key ID
    fn set_key_id(&mut self, key_id: &str);

    /// Remove a compared value for a kid header claim (kid).
    fn remove_key_id(&mut self);

    /// Return a signature of the data.
    ///
    /// # Arguments
    /// * `message` - The message data to sign.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError>;
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
    /// * `key_id` - a key ID
    fn set_key_id(&mut self, key_id: &str);

    /// Remove a compared value for a kid header claim (kid).
    fn remove_key_id(&mut self);

    /// Test a critical header claim name is acceptable.
    ///
    /// # Arguments
    /// * `name` - a critical header claim name
    fn is_acceptable_critical(&self, name: &str) -> bool;

    /// Add a acceptable critical header claim name
    ///
    /// # Arguments
    /// * `name` - a acceptable critical header claim name
    fn add_acceptable_critical(&mut self, name: &str);

    /// Remove a acceptable critical header claim name
    ///
    /// # Arguments
    /// * `name` - a acceptable critical header claim name
    fn remove_acceptable_critical(&mut self, name: &str);

    /// Verify the data by the signature.
    ///
    /// # Arguments
    /// * `message` - a message data to verify.
    /// * `signature` - a signature data.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError>;
}

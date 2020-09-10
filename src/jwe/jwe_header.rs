use std::cmp::Eq;
use std::collections::HashMap;
use std::convert::Into;
use std::fmt::{Debug, Display};
use std::ops::{Deref, DerefMut};

use anyhow::bail;
use serde_json::{Map, Value};

use crate::jose::{JoseError, JoseHeader};
use crate::jwk::Jwk;
use crate::util::SourceValue;

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

    /// Return a new header instance from json style header.
    ///
    /// # Arguments
    ///
    /// * `value` - The json style header claims
    pub fn from_bytes(value: &[u8]) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let claims: Map<String, Value> = serde_json::from_slice(value)?;
            Ok(Self::from_map(claims)?)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJson(err),
        })
    }

    /// Return a new header instance from map.
    ///
    /// # Arguments
    ///
    /// * `claims` - The header claims
    pub fn from_map(claims: Map<String, Value>) -> Result<Self, JoseError> {
        Ok(Self {
            claims,
            sources: HashMap::new(),
        })
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

    /// Set a value for issuer payload claim (iss).
    ///
    /// # Arguments
    ///
    /// * `value` - a issuer
    pub fn set_issuer(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("iss".to_string(), Value::String(value));
    }

    /// Return the value for issuer payload claim (iss).
    pub fn issuer(&self) -> Option<&str> {
        match self.claims.get("iss") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for subject payload claim (sub).
    ///
    /// # Arguments
    ///
    /// * `value` - a subject
    pub fn set_subject(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("sub".to_string(), Value::String(value));
    }

    /// Return the value for subject payload claim (sub).
    pub fn subject(&self) -> Option<&str> {
        match self.claims.get("sub") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set values for audience payload claim (aud).
    ///
    /// # Arguments
    ///
    /// * `values` - a list of audiences
    pub fn set_audience(&mut self, values: Vec<impl Into<String>>) {
        let key = "aud".to_string();
        if values.len() == 1 {
            for val in values {
                let val: String = val.into();
                self.sources.remove(&key);
                self.claims.insert(key, Value::String(val));
                break;
            }
        } else if values.len() > 1 {
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
    }

    /// Return values for audience payload claim (aud).
    pub fn audience(&self) -> Option<&Vec<String>> {
        match self.sources.get("aud") {
            Some(SourceValue::StringArray(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }
}

impl JoseHeader for JweHeader {
    fn claims_set(&self) -> &Map<String, Value> {
        &self.claims
    }

    fn set_claim(&mut self, key: &str, value: Option<Value>) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            match key {
                "alg" | "enc" | "zip" | "jku" | "x5u" | "kid" | "typ" | "cty" => match &value {
                    Some(Value::String(_)) => {
                        self.claims.insert(key.to_string(), value.unwrap());
                    }
                    None => {
                        self.claims.remove(key);
                    }
                    _ => bail!("The JWE {} header claim must be string.", key),
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
                    _ => bail!("The JWE {} header claim must be a string.", key),
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
                    _ => bail!("The JWE {} header claim must be a string.", key),
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
                    _ => bail!("The JWE {} header claim must be a string.", key),
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
                                    "An element of the JWE {} header claim must be a string.",
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
                    _ => bail!("The JWE {} header claim must be a array.", key),
                },
                "crit" => match &value {
                    Some(Value::Array(vals)) => {
                        let key = key.to_string();
                        let mut vec = Vec::with_capacity(vals.len());
                        for val in vals {
                            match val {
                                Value::String(val) => vec.push(val.to_string()),
                                _ => bail!(
                                    "An element of the JWE {} header claim must be a string.",
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
                    _ => bail!("The JWE {} header claim must be a array.", key),
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
        .map_err(|err| JoseError::InvalidJweFormat(err))
    }

    fn box_clone(&self) -> Box<dyn JoseHeader> {
        Box::new(self.clone())
    }

    fn into_map(self) -> Map<String, Value> {
        self.claims
    }
}

impl AsRef<Map<String, Value>> for JweHeader {
    fn as_ref(&self) -> &Map<String, Value> {
        &self.claims
    }
}

impl Into<Map<String, Value>> for JweHeader {
    fn into(self) -> Map<String, Value> {
        self.into_map()
    }
}

impl Display for JweHeader {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let val = serde_json::to_string(self.claims_set()).map_err(|_e| std::fmt::Error {})?;
        fmt.write_str(&val)
    }
}

impl Deref for JweHeader {
    type Target = dyn JoseHeader;

    fn deref(&self) -> &Self::Target {
        self
    }
}

impl DerefMut for JweHeader {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self
    }
}

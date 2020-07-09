use std::time::{Duration, SystemTime};

use anyhow::bail;
use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};

use crate::error::JoseError;
use crate::jwk::{Jwk, JwkSet};
use crate::jws::{JwsHeader, JwsAlgorithm, JwsSigner, JwsVerifier};

/// Represents plain JWT object with header and payload.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Jwt {
    jwk: Option<Jwk>,
    x509_certificate_sha1_thumbprint: Option<Vec<u8>>,
    x509_certificate_sha256_thumbprint: Option<Vec<u8>>,
    x509_certificate_chain: Option<Vec<Vec<u8>>>,
    critical: Option<Vec<String>>,
    header: Map<String, Value>,

    audience: Option<Vec<String>>,
    expires_at: Option<SystemTime>,
    not_before: Option<SystemTime>,
    issued_at: Option<SystemTime>,
    payload: Map<String, Value>,
}

impl JwsHeader for Map<String, Value> {
    fn algorithm(&self) -> Option<&str> {
        match self.get("alg") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn key_id(&self) -> Option<&str> {
        match self.get("kid") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn token_type(&self) -> Option<&str> {
        match self.get("typ") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn content_type(&self) -> Option<&str> {
        match self.get("cty") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    fn header_claim(&self, key: &str) -> Option<&Value> {
        self.get(key)
    }
}

impl Jwt {
    /// Return the new JWT object that has only a "JWT" type header claim.
    pub fn new() -> Self {
        let mut header = Map::default();
        header.insert("typ".to_string(), json!("JWT"));

        Self {
            jwk: None,
            x509_certificate_sha1_thumbprint: None,
            x509_certificate_sha256_thumbprint: None,
            x509_certificate_chain: None,
            critical: None,
            header: header,

            audience: None,
            expires_at: None,
            not_before: None,
            issued_at: None,
            payload: Map::default(),
        }
    }

    /// Return the JWT object from header and payload claims.
    ///
    /// # Arguments
    /// * `header` - JWT header claims.
    /// * `payload` - JWT payload claims.
    pub fn from_map(
        header: Map<String, Value>,
        payload: Map<String, Value>,
    ) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let mut jwk = None;
            let mut x509_certificate_sha1_thumbprint = None;
            let mut x509_certificate_sha256_thumbprint = None;
            let mut x509_certificate_chain = None;
            let mut critical = None;
            for (key, value) in &header {
                match key.as_ref() {
                    "jku" | "x5u" | "kid" | "typ" | "cty" => match value {
                        Value::String(_) => {},
                        _ => bail!("The JWT {} header claim must be a string.", key),
                    },
                    "jwk" => jwk = match value {
                        Value::Object(vals) => Some(Jwk::from_map(vals.clone())?),
                        _ => bail!("The JWT {} header claim must be a string.", key),
                    },
                    "x5t" => x509_certificate_sha1_thumbprint = match value {
                        Value::String(val) => Some(base64::decode_config(val, base64::URL_SAFE_NO_PAD)?),
                        _ => bail!("The JWT {} header claim must be a string.", key),
                    },
                    "x5t#S256" => x509_certificate_sha256_thumbprint = match value {
                        Value::String(val) => Some(base64::decode_config(val, base64::URL_SAFE_NO_PAD)?),
                        _ => bail!("The JWT {} header claim must be a string.", key),
                    },
                    "x5c" => x509_certificate_chain = match value {
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
                            Some(vec)
                        },
                        _ => bail!("The JWT {} header claim must be a array.", key),
                    },
                    "crit" => critical = match value {
                        Value::Array(vals) => {
                            let mut vec = Vec::with_capacity(vals.len());
                            for val in vals {
                                match val {
                                    Value::String(val) => vec.push(val.to_string()),
                                    _ => bail!("An element of the JWT {} header claim must be a string.", key),
                                }
                            }
                            Some(vec)
                        },
                        _ => bail!("The JWT {} header claim must be a array.", key),
                    },
                    _ => {},
                }
            }

            let mut audience = None;
            let mut expires_at = None;
            let mut not_before = None;
            let mut issued_at = None;
            for (key, value) in &payload {
                match key.as_ref() {
                    "iss" | "sub" | "jti" => match value {
                        Value::String(_) => {},
                        _ => bail!("The JWT {} payload claim must be a string.", key),
                    },
                    "aud" => audience = match value {
                        Value::String(val) => Some(vec![val.clone()]),
                        Value::Array(vals) => {
                            let mut vec = Vec::with_capacity(vals.len());
                            for val in vals {
                                match val {
                                    Value::String(val) => vec.push(val.to_string()),
                                    _ => bail!("An element of JWT {} payload claim must be a string.", key),
                                }
                            }
                            Some(vec)
                        },
                        _ => bail!("The JWT {} payload claim must be a string or array.", key),
                    },
                    "exp" => expires_at = match value {
                        Value::Number(val) => match val.as_u64() {
                            Some(val) => Some(SystemTime::UNIX_EPOCH + Duration::from_secs(val)),
                            None => bail!("The JWT {} payload claim must be a positive integer within 64bit.", key),
                        },
                        _ => bail!("The JWT {} payload claim must be a string type.", key),
                    },
                    "nbf" => not_before = match value {
                        Value::Number(val) => match val.as_u64() {
                            Some(val) => Some(SystemTime::UNIX_EPOCH + Duration::from_secs(val)),
                            None => bail!("The JWT {} payload claim must be a positive integer within 64bit.", key),
                        },
                        _ => bail!("The JWT {} payload claim must be a string type.", key),
                    },
                    "iat" => issued_at = match value {
                        Value::Number(val) => match val.as_u64() {
                            Some(val) => Some(SystemTime::UNIX_EPOCH + Duration::from_secs(val)),
                            None => bail!("The JWT {} payload claim must be a positive integer within 64bit.", key),
                        },
                        _ => bail!("The JWT {} payload claim must be a string type.", key),
                    },
                    _ => {},
                }
            }

            Ok(Self {
                jwk,
                x509_certificate_sha1_thumbprint,
                x509_certificate_sha256_thumbprint,
                x509_certificate_chain,
                critical,
                header,
                audience,
                expires_at,
                not_before,
                issued_at,
                payload,
            })
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err)
        })
    }

    /// Return the JWT object decoded with the "none" algorithm.
    ///
    /// # Arguments
    /// * `input` - a JWT string representation.
    pub fn decode_with_none(input: &str) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let parts: Vec<&str> = input.split('.').collect();
            if parts.len() != 2 {
                bail!("The unsecured JWT must be two parts separated by colon.");
            }

            let header_base64 = parts.get(0).unwrap();
            let header_json = base64::decode_config(header_base64, base64::URL_SAFE_NO_PAD)?;
            let mut header: Map<String, Value> = serde_json::from_slice(&header_json)?;

            match header.get("alg") {
                Some(Value::String(val)) if val == "none" => {}
                Some(Value::String(val)) => bail!("The JWT alg header claim is not none: {}", val),
                Some(_) => bail!("The JWT alg header claim must be a string."),
                None => bail!("The JWT alg header claim is missing."),
            }

            match header.get("kid") {
                None => {}
                Some(_) => bail!("A JWT of none alg cannot have kid header claim."),
            }

            header.remove("alg");

            let payload_base64 = parts.get(1).unwrap();
            let payload_json = base64::decode_config(payload_base64, base64::URL_SAFE_NO_PAD)?;
            let payload: Map<String, Value> = serde_json::from_slice(&payload_json)?;

            Ok(Self::from_map(header, payload)?)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err),
        })
    }

    /// Return the JWT object decoded by the selected verifier.
    ///
    /// # Arguments
    /// * `input` - a JWT string representation.
    /// * `verifier` - a verifier of the signing algorithm.
    pub fn decode_with_verifier(
        input: &str,
        verifier: impl AsRef<dyn JwsVerifier>,
    ) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Jwt> {
            let verifier = verifier.as_ref();

            let parts: Vec<&str> = input.split('.').collect();
            if parts.len() != 3 {
                bail!("The signed JWT must be three parts separated by colon.");
            }
    
            let header = base64::decode_config(&parts[0], base64::URL_SAFE_NO_PAD)?;
            let mut header: Map<String, Value> = serde_json::from_slice(&header)?;

            let payload = verifier.deserialize_compact(&header, input)?;
            let payload: Map<String, Value> = serde_json::from_slice(&payload)?;

            header.remove("alg");

            let jwt = Self::from_map(header, payload)?;
            Ok(jwt)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err),
        })
    }

    /// Return the JWT object decoded by using a JWK set.
    ///
    /// # Arguments
    /// * `input` - a JWT string representation.
    /// * `algorithm` - a verifying algorithm.
    /// * `jwk_set` - a JWK set.
    pub fn decode_by_jwk_set(
        input: &str,
        algorithm: impl AsRef<dyn JwsAlgorithm>,
        jwk_set: &JwkSet,
    ) -> Result<Self, JoseError> {
        let algorithm = algorithm.as_ref();
        Self::decode_with_verifier_selector(input, |header| -> Option<Box<dyn JwsVerifier>> {
            let key_id = match header.key_id() {
                Some(val) => val,
                None => return None,
            };

            for jwk in jwk_set.get(key_id) {
                match algorithm.verifier_from_jwk(jwk) {
                    Ok(val) => return Some(val),
                    Err(_) => {}
                }
            }
            None
        })
    }

    /// Return the JWT object decoded with a selected verifying algorithm.
    ///
    /// # Arguments
    /// * `input` - a JWT string representation.
    /// * `verifier_selector` - a function for selecting the verifying algorithm.
    pub fn decode_with_verifier_selector<F>(
        input: &str,
        verifier_selector: F,
    ) -> Result<Self, JoseError>
    where
        F: FnOnce(&dyn JwsHeader) -> Option<Box<dyn JwsVerifier>>,
    {
        (|| -> anyhow::Result<Jwt> {
            let parts: Vec<&str> = input.split('.').collect();
            if parts.len() != 3 {
                bail!("The signed JWT must be three parts separated by colon.");
            }

            let header = base64::decode_config(&parts[0], base64::URL_SAFE_NO_PAD)?;
            let mut header: Map<String, Value> = serde_json::from_slice(&header)?;

            let verifier = match verifier_selector(&header) {
                Some(val) => val,
                None => bail!("A verifier is not found."),
            };

            let payload = verifier.deserialize_compact(&header, input)?;
            let payload: Map<String, Value> = serde_json::from_slice(&payload)?;
            
            header.remove("alg");

            let jwt = Self::from_map(header, payload)?;
            Ok(jwt)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err),
        })
    }

    /// Set a value for JWK set URL header claim (jku).
    ///
    /// # Arguments
    /// * `value` - a JWK set URL
    pub fn set_jwk_set_url(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.header.insert("jku".to_string(), Value::String(value));
    }

    /// Return the value for JWK set URL header claim (jku).
    pub fn jwk_set_url(&self) -> Option<&str> {
        match self.header.get("jku") {
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
        self.header
            .insert("jwk".to_string(), Value::Object(value.as_ref().clone()));
        self.jwk = Some(value);
    }

    /// Return the value for JWK header claim (jwk).
    pub fn jwk(&self) -> Option<&Jwk> {
        match self.jwk {
            Some(ref val) => Some(val),
            None => None,
        }
    }

    /// Set a value for X.509 URL header claim (x5u).
    ///
    /// # Arguments
    /// * `value` - a X.509 URL
    pub fn set_x509_url(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.header.insert("x5u".to_string(), Value::String(value));
    }

    /// Return a value for a X.509 URL header claim (x5u).
    pub fn x509_url(&self) -> Option<&str> {
        match self.header.get("x5u") {
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
        let mut vec = Vec::with_capacity(values.len());
        for val in &values {
            vec.push(Value::String(base64::encode_config(
                &val,
                base64::URL_SAFE_NO_PAD,
            )));
        }
        self.header.insert("x5c".to_string(), Value::Array(vec));
        self.x509_certificate_chain = Some(values);
    }

    /// Return values for a X.509 certificate chain header claim (x5c).
    pub fn x509_certificate_chain(&self) -> Option<&Vec<Vec<u8>>> {
        match self.x509_certificate_chain {
            Some(ref val) => Some(val),
            None => None,
        }
    }

    /// Set a value for X.509 certificate SHA-1 thumbprint header claim (x5t).
    ///
    /// # Arguments
    /// * `value` - A X.509 certificate SHA-1 thumbprint
    pub fn set_x509_certificate_sha1_thumbprint(&mut self, value: Vec<u8>) {
        self.header.insert(
            "x5t".to_string(),
            Value::String(base64::encode_config(&value, base64::URL_SAFE_NO_PAD)),
        );
        self.x509_certificate_sha1_thumbprint = Some(value);
    }

    /// Return the value for X.509 certificate SHA-1 thumbprint header claim (x5t).
    pub fn x509_certificate_sha1_thumbprint(&self) -> Option<&Vec<u8>> {
        match self.x509_certificate_sha1_thumbprint {
            Some(ref val) => Some(val),
            None => None,
        }
    }

    /// Set a value for a x509 certificate SHA-256 thumbprint header claim (x5t#S256).
    ///
    /// # Arguments
    /// * `value` - A x509 certificate SHA-256 thumbprint
    pub fn set_x509_certificate_sha256_thumbprint(&mut self, value: Vec<u8>) {
        self.header.insert(
            "x5t#S256".to_string(),
            Value::String(base64::encode_config(&value, base64::URL_SAFE_NO_PAD)),
        );
        self.x509_certificate_sha256_thumbprint = Some(value);
    }

    /// Return the value for X.509 certificate SHA-256 thumbprint header claim (x5t#S256).
    pub fn x509_certificate_sha256_thumbprint(&self) -> Option<&Vec<u8>> {
        match self.x509_certificate_sha256_thumbprint {
            Some(ref val) => Some(val),
            None => None,
        }
    }

    /// Set a value for key ID header claim (kid).
    ///
    /// # Arguments
    /// * `value` - a key ID
    pub fn set_key_id(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.header.insert("kid".to_string(), Value::String(value));
    }

    /// Return the value for key ID header claim (kid).
    pub fn key_id(&self) -> Option<&str> {
        match self.header.get("kid") {
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
        self.header.insert("typ".to_string(), Value::String(value));
    }

    /// Return the value for token type header claim (typ).
    pub fn token_type(&self) -> Option<&str> {
        match self.header.get("typ") {
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
        self.header.insert("cty".to_string(), Value::String(value));
    }

    /// Return the value for content type header claim (cty).
    pub fn content_type(&self) -> Option<&str> {
        match self.header.get("cty") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set values for critical header claim (crit).
    ///
    /// # Arguments
    /// * `values` - critical claim names
    pub fn set_critical(&mut self, values: Vec<impl Into<String>>) {
        let mut vec1 = Vec::with_capacity(values.len());
        let mut vec2 = Vec::with_capacity(values.len());
        for val in values {
            let val: String = val.into();
            vec1.push(Value::String(val.clone()));
            vec2.push(val);
        }
        self.header.insert("crit".to_string(), Value::Array(vec1));
        self.critical = Some(vec2);
    }

    /// Return values for critical header claim (crit).
    pub fn critical(&self) -> Option<&Vec<String>> {
        match self.critical {
            Some(ref val) => Some(val),
            None => None,
        }
    }

    /// Set a value for header claim of a specified key.
    ///
    /// # Arguments
    /// * `key` - a key name of header claim
    /// * `value` - a typed value of header claim
    pub fn set_header_claim(&mut self, key: &str, value: Option<Value>) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            match key {
                "alg" => bail!(
                    "The JWT {} header claim should not be setted expressly.",
                    key
                ),
                "jku" | "x5u" | "kid" | "typ" | "cty" => match &value {
                    Some(Value::String(_)) => {
                        self.header.insert(key.to_string(), value.unwrap());
                    }
                    None => {
                        self.header.remove(key);
                    }
                    _ => bail!("The JWT {} header claim must be string.", key),
                },
                "jwk" => match &value {
                    Some(Value::Object(vals)) => {
                        self.jwk = Some(Jwk::from_map(vals.clone())?);
                        self.header.insert(key.to_string(), value.unwrap());
                    }
                    None => {
                        self.jwk = None;
                        self.header.remove(key);
                    }
                    _ => bail!("The JWT {} header claim must be a string.", key),
                },
                "x5t" => match &value {
                    Some(Value::String(val)) => {
                        self.x509_certificate_sha1_thumbprint =
                            Some(base64::decode_config(val, base64::URL_SAFE_NO_PAD)?);
                        self.header.insert(key.to_string(), value.unwrap());
                    }
                    None => {
                        self.x509_certificate_sha1_thumbprint = None;
                        self.header.remove(key);
                    }
                    _ => bail!("The JWT {} header claim must be a string.", key),
                },
                "x5t#S256" => match &value {
                    Some(Value::String(val)) => {
                        self.x509_certificate_sha256_thumbprint =
                            Some(base64::decode_config(val, base64::URL_SAFE_NO_PAD)?);
                        self.header.insert(key.to_string(), value.unwrap());
                    }
                    None => {
                        self.x509_certificate_sha256_thumbprint = None;
                        self.header.remove(key);
                    }
                    _ => bail!("The JWT {} header claim must be a string.", key),
                },
                "x5c" => match &value {
                    Some(Value::Array(vals)) => {
                        let mut vec = Vec::with_capacity(vals.len());
                        for val in vals {
                            match val {
                                Value::String(val) => {
                                    let decoded =
                                        base64::decode_config(val, base64::URL_SAFE_NO_PAD)?;
                                    vec.push(decoded);
                                }
                                _ => bail!(
                                    "An element of the JWT {} header claim must be a string.",
                                    key
                                ),
                            }
                        }
                        self.x509_certificate_chain = Some(vec);
                        self.header.insert(key.to_string(), value.unwrap());
                    }
                    None => {
                        self.x509_certificate_chain = None;
                        self.header.remove(key);
                    }
                    _ => bail!("The JWT {} header claim must be a array.", key),
                },
                "crit" => match &value {
                    Some(Value::Array(vals)) => {
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
                        self.critical = Some(vec);
                        self.header.insert(key.to_string(), value.unwrap());
                    }
                    None => {
                        self.critical = None;
                        self.header.remove(key);
                    }
                    _ => bail!("The JWT {} header claim must be a array.", key),
                },
                _ => match &value {
                    Some(_) => {
                        self.header.insert(key.to_string(), value.unwrap());
                    }
                    None => {
                        self.header.remove(key);
                    }
                },
            }

            Ok(())
        })()
        .map_err(|err| JoseError::InvalidJwtFormat(err))
    }

    /// Return the value for header claim of a specified key.
    ///
    /// # Arguments
    /// * `key` - a key name of header claim
    pub fn header_claim(&self, key: &str) -> Option<&Value> {
        self.header.get(key)
    }

    /// Return values for header claims set
    pub fn header_claims_set(&self) -> &Map<String, Value> {
        &self.header
    }

    /// Set a value for issuer payload claim (iss).
    ///
    /// # Arguments
    /// * `value` - a issuer
    pub fn set_issuer(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.payload.insert("iss".to_string(), Value::String(value));
    }

    /// Return the value for issuer payload claim (iss).
    pub fn issuer(&self) -> Option<&str> {
        match self.payload.get("iss") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for subject payload claim (sub).
    ///
    /// # Arguments
    /// * `value` - a subject
    pub fn set_subject(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.payload.insert("sub".to_string(), Value::String(value));
    }

    /// Return the value for subject payload claim (sub).
    pub fn subject(&self) -> Option<&str> {
        match self.payload.get("sub") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set values for audience payload claim (aud).
    ///
    /// # Arguments
    /// * `values` - a list of audiences
    pub fn set_audience(&mut self, values: Vec<impl Into<String>>) {
        if values.len() == 0 {
            for val in values {
                let val: String = val.into();
                self.payload
                    .insert("aud".to_string(), Value::String(val.clone()));
                self.audience = Some(vec![val]);
                break;
            }
        } else {
            let mut vec1 = Vec::with_capacity(values.len());
            let mut vec2 = Vec::with_capacity(values.len());
            for val in values {
                let val: String = val.into();
                vec1.push(Value::String(val.clone()));
                vec2.push(val);
            }
            self.payload.insert("aud".to_string(), Value::Array(vec1));
            self.audience = Some(vec2);
        }
    }

    /// Return values for audience payload claim (aud).
    pub fn audience(&self) -> Option<&Vec<String>> {
        self.audience.as_ref()
    }

    /// Set a system time for expires at payload claim (exp).
    ///
    /// # Arguments
    /// * `value` - A expiration time on or after which the JWT must not be accepted for processing.
    pub fn set_expires_at(&mut self, value: SystemTime) {
        self.payload.insert(
            "exp".to_string(),
            json!(value
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()),
        );
        self.expires_at = Some(value);
    }

    /// Return the system time for expires at payload claim (exp).
    pub fn expires_at(&self) -> Option<&SystemTime> {
        self.expires_at.as_ref()
    }

    /// Set a system time for not before payload claim (nbf).
    ///
    /// # Arguments
    /// * `value` - A time before which the JWT must not be accepted for processing.
    pub fn set_not_before(&mut self, value: SystemTime) {
        self.payload.insert(
            "nbf".to_string(),
            json!(value
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()),
        );
        self.not_before = Some(value);
    }

    /// Return the system time for not before payload claim (nbf).
    pub fn not_before(&self) -> Option<&SystemTime> {
        self.not_before.as_ref()
    }

    /// Set a time for issued at payload claim (iat).
    ///
    /// # Arguments
    /// * `value` - a time at which the JWT was issued.
    pub fn set_issued_at(&mut self, value: SystemTime) {
        self.payload.insert(
            "iat".to_string(),
            json!(value
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()),
        );
        self.issued_at = Some(value);
    }

    /// Return the time for a issued at payload claim (iat).
    pub fn issued_at(&self) -> Option<&SystemTime> {
        self.issued_at.as_ref()
    }

    /// Set a value for JWT ID payload claim (jti).
    ///
    /// # Arguments
    /// * `value` - a JWT ID
    pub fn set_jwt_id(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.payload.insert("jti".to_string(), json!(value));
    }

    /// Return the value for JWT ID payload claim (jti).
    pub fn jwt_id(&self) -> Option<&str> {
        match self.payload.get("jti") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for payload claim of a specified key.
    ///
    /// # Arguments
    /// * `key` - a key name of payload claim
    /// * `value` - a typed value of payload claim
    pub fn set_payload_claim(&mut self, key: &str, value: Option<Value>) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            match key {
                "iss" | "sub" | "jti" => match &value {
                    Some(Value::String(_)) => {
                        self.payload.insert(key.to_string(), value.unwrap());
                    }
                    None => {
                        self.payload.remove(key);
                    }
                    _ => bail!("The JWT {} payload claim must be a string.", key),
                },
                "aud" => match &value {
                    Some(Value::String(val)) => {
                        self.audience = Some(vec![val.clone()]);
                        self.payload.insert(key.to_string(), value.unwrap());
                    }
                    Some(Value::Array(vals)) => {
                        let mut vec = Vec::with_capacity(vals.len());
                        for val in vals {
                            match val {
                                Value::String(val) => vec.push(val.to_string()),
                                _ => bail!(
                                    "An element of the JWT {} payload claim must be a string.",
                                    key
                                ),
                            }
                        }
                        self.audience = Some(vec);
                        self.payload.insert(key.to_string(), value.unwrap());
                    }
                    None => {
                        self.audience = None;
                        self.payload.remove(key);
                    }
                    _ => bail!("The JWT {} payload claim must be a string or array.", key),
                },
                "exp" => match &value {
                    Some(Value::Number(val)) => match val.as_u64() {
                        Some(val) => {
                            self.expires_at =
                                Some(SystemTime::UNIX_EPOCH + Duration::from_secs(val));
                            self.payload.insert(key.to_string(), value.unwrap());
                        }
                        None => bail!(
                            "The JWT {} payload claim must be a positive integer within 64bit.",
                            key
                        ),
                    },
                    None => {
                        self.expires_at = None;
                        self.payload.remove(key);
                    }
                    _ => bail!("The JWT {} header claim must be a string.", key),
                },
                "nbf" => match &value {
                    Some(Value::Number(val)) => match val.as_u64() {
                        Some(val) => {
                            self.not_before =
                                Some(SystemTime::UNIX_EPOCH + Duration::from_secs(val));
                            self.payload.insert(key.to_string(), value.unwrap());
                        }
                        None => bail!(
                            "The JWT {} payload claim must be a positive integer within 64bit.",
                            key
                        ),
                    },
                    None => {
                        self.not_before = None;
                        self.payload.remove(key);
                    }
                    _ => bail!("The JWT {} payload claim must be a string.", key),
                },
                "iat" => match &value {
                    Some(Value::Number(val)) => match val.as_u64() {
                        Some(val) => {
                            self.issued_at =
                                Some(SystemTime::UNIX_EPOCH + Duration::from_secs(val));
                            self.payload.insert(key.to_string(), value.unwrap());
                        }
                        None => bail!(
                            "The JWT {} payload claim must be a positive integer within 64bit.",
                            key
                        ),
                    },
                    None => {
                        self.issued_at = None;
                        self.payload.remove(key);
                    }
                    _ => bail!("The JWT {} payload claim must be a string.", key),
                },
                _ => match &value {
                    Some(_) => {
                        self.payload.insert(key.to_string(), value.unwrap());
                    }
                    None => {
                        self.payload.remove(key);
                    }
                },
            }

            Ok(())
        })()
        .map_err(|err| JoseError::InvalidJwtFormat(err))
    }

    /// Return a value for payload claim of a specified key.
    ///
    /// # Arguments
    /// * `key` - a key name of payload claim
    pub fn payload_claim(&self, key: &str) -> Option<&Value> {
        self.payload.get(key)
    }

    /// Return values for payload claims set
    pub fn payload_claims_set(&self) -> &Map<String, Value> {
        &self.payload
    }

    /// Return the string repsentation of the JWT with a "none" algorithm.
    pub fn encode_with_none(&self) -> Result<String, JoseError> {
        let mut header = self.header.clone();
        header.insert("alg".to_string(), json!("none"));

        let header = serde_json::to_string(&header).unwrap();
        let header = base64::encode_config(header, base64::URL_SAFE_NO_PAD);

        let payload = serde_json::to_string(&self.payload).unwrap();
        let payload = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);

        Ok(format!("{}.{}", header, payload))
    }

    /// Return the string repsentation of the JWT with the siginig algorithm.
    ///
    /// # Arguments
    ///
    /// * `signer` - a signer object.
    pub fn encode_with_signer(
        &self,
        signer: impl AsRef<dyn JwsSigner>,
    ) -> Result<String, JoseError> {
        let signer = signer.as_ref();
        let name = signer.algorithm().name();

        let mut header = self.header.clone();
        header.insert("alg".to_string(), json!(name));

        if let Some(key_id) = signer.key_id() {
            header.insert("kid".to_string(), json!(key_id));
        }

        let payload_json = serde_json::to_string(&self.payload).unwrap();
        let jwt = signer.serialize_compact(&header, &payload_json.as_bytes())?;
        Ok(jwt)
    }
}

impl Default for Jwt {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents JWT validator.
#[derive(Debug, Eq, PartialEq)]
pub struct JwtValidator {
    base_time: Option<SystemTime>,
    min_issued_time: Option<SystemTime>,
    max_issued_time: Option<SystemTime>,
    audience: Option<String>,
    payload: Map<String, Value>,
}

impl JwtValidator {
    /// Set a base time for time related claims (exp, nbf) validation.
    ///
    /// # Arguments
    /// * `base_time` - a min time
    pub fn set_base_time(&mut self, base_time: SystemTime) {
        self.base_time = Some(base_time);
    }

    /// Return the base time for time related claims (exp, nbf) validation.
    pub fn base_time(&self) -> Option<&SystemTime> {
        self.base_time.as_ref()
    }

    /// Set a minimum time for issued at payload claim (iat) validation.
    ///
    /// # Arguments
    /// * `min_issued_time` - a minimum time at which the JWT was issued.
    pub fn set_min_issued_time(&mut self, min_issued_time: SystemTime) {
        self.min_issued_time = Some(min_issued_time);
    }

    /// Return the minimum time for issued at payload claim (iat).
    pub fn min_issued_time(&self) -> Option<&SystemTime> {
        self.min_issued_time.as_ref()
    }

    /// Set a maximum time for issued at payload claim (iat) validation.
    ///
    /// # Arguments
    /// * `max_issued_time` - a maximum time at which the JWT was issued.
    pub fn set_max_issued_time(&mut self, max_issued_time: SystemTime) {
        self.max_issued_time = Some(max_issued_time);
    }

    /// Return the maximum time for issued at payload claim (iat).
    pub fn max_issued_time(&self) -> Option<&SystemTime> {
        self.max_issued_time.as_ref()
    }

    /// Set a value for issuer payload claim (iss) validation.
    ///
    /// # Arguments
    /// * `value` - a issuer
    pub fn set_issuer(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.payload.insert("iss".to_string(), Value::String(value));
    }

    /// Return the value for issuer payload claim (iss) validation.
    pub fn issuer(&self) -> Option<&str> {
        match self.payload.get("iss") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for subject payload claim (sub) validation.
    ///
    /// # Arguments
    /// * `value` - a subject
    pub fn set_subject(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.payload.insert("sub".to_string(), Value::String(value));
    }

    /// Return the value for subject payload claim (sub) validation.
    pub fn subject(&self) -> Option<&str> {
        match self.payload.get("sub") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for audience payload claim (aud) validation.
    ///
    /// # Arguments
    /// * `value` - a audience
    pub fn set_audience(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.audience = Some(value);
    }

    /// Return the value for audience payload claim (aud) validation.
    pub fn audience(&self) -> Option<&str> {
        match self.audience {
            Some(ref val) => Some(val),
            _ => None,
        }
    }

    /// Set a value for JWT ID payload claim (jti) validation.
    ///
    /// # Arguments
    /// * `value` - A JWT ID
    pub fn set_jwt_id(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.payload.insert("jti".to_string(), Value::String(value));
    }

    /// Return the value for JWT ID payload claim (jti) validation.
    pub fn jwt_id(&self) -> Option<&str> {
        match self.payload.get("jti") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for payload claim of a specified key.
    ///
    /// # Arguments
    /// * `key` - a key name of payload claim
    /// * `value` - a typed value of payload claim
    pub fn set_payload_claim(&mut self, key: &str, value: Value) {
        self.payload.insert(key.to_string(), value);
    }

    /// Return the value for payload claim of a specified key.
    ///
    /// # Arguments
    /// * `key` - a key name of payload claim
    pub fn payload_claim(&self, key: &str) -> Option<&Value> {
        self.payload.get(key)
    }

    /// Validate a decoded JWT object.
    ///
    /// # Arguments
    /// * `jwt` - a decoded JWT object.
    pub fn validate(&self, jwt: &Jwt) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            let now = SystemTime::now();
            let current_time = self.base_time().unwrap_or(&now);
            let min_issued_time = self.min_issued_time().unwrap_or(&SystemTime::UNIX_EPOCH);
            let max_issued_time = self.max_issued_time().unwrap_or(&now);

            if let Some(not_before) = jwt.not_before() {
                if not_before > &current_time {
                    bail!(
                        "The token is not yet valid: {}",
                        DateTime::<Utc>::from(*not_before)
                    );
                }
            }

            if let Some(expires_at) = jwt.expires_at() {
                if expires_at <= &current_time {
                    bail!(
                        "The token has expired: {}",
                        DateTime::<Utc>::from(*expires_at)
                    );
                }
            }

            if let Some(issued_at) = jwt.issued_at() {
                if issued_at < &min_issued_time {
                    bail!(
                        "The issued time is too old: {}",
                        DateTime::<Utc>::from(*issued_at)
                    );
                }

                if issued_at < &max_issued_time {
                    bail!(
                        "The issued time is too new: {}",
                        DateTime::<Utc>::from(*issued_at)
                    );
                }
            }

            for (key, value1) in &self.payload {
                if let Some(value2) = jwt.payload_claim(key) {
                    if value1 != value2 {
                        bail!("Key {} is invalid: {}", key, value2);
                    }
                } else {
                    bail!("Key {} is missing.", key);
                }
            }

            Ok(())
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidClaim(err),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Result;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;

    use crate::jws::{
        ES256, ES256K, ES384, ES512, HS256, HS384, HS512, PS256, PS384, PS512, RS256, RS384, RS512, EDDSA
    };

    #[test]
    fn test_new_jwt() -> Result<()> {
        let mut jwt = Jwt::new();
        let jwk = Jwk::new("oct");
        jwt.set_jwk_set_url("jku");
        jwt.set_jwk(jwk.clone());
        jwt.set_x509_url("x5u");
        jwt.set_x509_certificate_chain(vec![b"x5c0".to_vec(), b"x5c1".to_vec()]);
        jwt.set_x509_certificate_sha1_thumbprint(b"x5t".to_vec());
        jwt.set_x509_certificate_sha256_thumbprint(b"x5t#S256".to_vec());
        jwt.set_key_id("kid");
        jwt.set_token_type("typ");
        jwt.set_content_type("cty");
        jwt.set_critical(vec!["crit0", "crit1"]);
        jwt.set_header_claim("header_claim", Some(json!("header_claim")))?;

        jwt.set_issuer("iss");
        jwt.set_subject("sub");
        jwt.set_audience(vec!["aud0", "aud1"]);
        jwt.set_expires_at(SystemTime::UNIX_EPOCH);
        jwt.set_not_before(SystemTime::UNIX_EPOCH);
        jwt.set_issued_at(SystemTime::UNIX_EPOCH);
        jwt.set_jwt_id("jti");
        jwt.set_payload_claim("payload_claim", Some(json!("payload_claim")))?;

        assert!(matches!(jwt.jwk_set_url(), Some("jku")));
        assert!(matches!(jwt.jwk(), Some(val) if val == &jwk));
        assert!(matches!(jwt.x509_url(), Some("x5u")));
        assert!(
            matches!(jwt.x509_certificate_chain(), Some(vals) if vals == &vec![
                b"x5c0".to_vec(),
                b"x5c1".to_vec(),
            ])
        );
        assert!(
            matches!(jwt.x509_certificate_sha1_thumbprint(), Some(val) if val == &b"x5t".to_vec())
        );
        assert!(
            matches!(jwt.x509_certificate_sha256_thumbprint(), Some(val) if val == &b"x5t#S256".to_vec())
        );
        assert!(matches!(jwt.key_id(), Some("kid")));
        assert!(matches!(jwt.token_type(), Some("typ")));
        assert!(matches!(jwt.content_type(), Some("cty")));
        assert!(matches!(jwt.critical(), Some(vals) if vals == &vec!["crit0", "crit1"]));
        assert!(
            matches!(jwt.header_claim("header_claim"), Some(val) if val == &json!("header_claim"))
        );

        assert!(matches!(jwt.issuer(), Some("iss")));
        assert!(matches!(jwt.subject(), Some("sub")));
        assert!(matches!(jwt.audience(), Some(vals) if vals == &vec!["aud0", "aud1"]));
        assert!(matches!(jwt.expires_at(), Some(val) if val == &SystemTime::UNIX_EPOCH));
        assert!(matches!(jwt.not_before(), Some(val) if val == &SystemTime::UNIX_EPOCH));
        assert!(matches!(jwt.issued_at(), Some(val) if val == &SystemTime::UNIX_EPOCH));
        assert!(matches!(jwt.jwt_id(), Some("jti")));
        assert!(
            matches!(jwt.payload_claim("payload_claim"), Some(val) if val == &json!("payload_claim"))
        );

        Ok(())
    }

    #[test]
    fn test_jwt_with_none() -> Result<()> {
        let from_jwt = Jwt::new();

        let jwt_string = from_jwt.encode_with_none()?;
        let to_jwt = Jwt::decode_with_none(&jwt_string)?;

        assert_eq!(from_jwt, to_jwt);

        Ok(())
    }

    #[test]
    fn test_jwt_with_hmac() -> Result<()> {
        let from_jwt = Jwt::new();

        for alg in &[HS256, HS384, HS512] {
            let private_key = b"quety12389";
            let signer = alg.signer_from_slice(private_key)?;
            let jwt_string = from_jwt.encode_with_signer(&signer)?;

            let verifier = alg.verifier_from_slice(private_key)?;
            let to_jwt = Jwt::decode_with_verifier(&jwt_string, &verifier)?;

            assert_eq!(from_jwt, to_jwt);
        }

        Ok(())
    }

    #[test]
    fn test_jwt_with_rsa_pem() -> Result<()> {
        let from_jwt = Jwt::new();

        for alg in &[RS256, RS384, RS512] {
            let private_key = load_file("pem/RSA_2048bit_pkcs8_private.pem")?;
            let public_key = load_file("pem/RSA_2048bit_pkcs8_public.pem")?;

            let signer = alg.signer_from_pem(&private_key)?;
            let jwt_string = from_jwt.encode_with_signer(&signer)?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            let to_jwt = Jwt::decode_with_verifier(&jwt_string, &verifier)?;

            assert_eq!(from_jwt, to_jwt);
        }

        Ok(())
    }

    #[test]
    fn test_jwt_with_rsapss_pem() -> Result<()> {
        let from_jwt = Jwt::new();

        for alg in &[PS256, PS384, PS512] {
            let private_key = load_file(match alg.name() {
                "PS256" => "pem/RSA-PSS_2048bit_SHA256_pkcs8_private.pem",
                "PS384" => "pem/RSA-PSS_2048bit_SHA384_pkcs8_private.pem",
                "PS512" => "pem/RSA-PSS_2048bit_SHA512_pkcs8_private.pem",
                _ => unreachable!(),
            })?;
            let public_key = load_file(match alg.name() {
                "PS256" => "pem/RSA-PSS_2048bit_SHA256_pkcs8_public.pem",
                "PS384" => "pem/RSA-PSS_2048bit_SHA384_pkcs8_public.pem",
                "PS512" => "pem/RSA-PSS_2048bit_SHA512_pkcs8_public.pem",
                _ => unreachable!(),
            })?;

            let signer = alg.signer_from_pem(&private_key)?;
            let jwt_string = from_jwt.encode_with_signer(&signer)?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            let to_jwt = Jwt::decode_with_verifier(&jwt_string, &verifier)?;

            assert_eq!(from_jwt, to_jwt);
        }

        Ok(())
    }

    #[test]
    fn test_jwt_with_rsa_der() -> Result<()> {
        let from_jwt = Jwt::new();

        for alg in &[RS256, RS384, RS512] {
            let private_key = load_file("der/RSA_2048bit_pkcs8_private.der")?;
            let public_key = load_file("der/RSA_2048bit_pkcs8_public.der")?;

            let signer = alg.signer_from_der(&private_key)?;
            let jwt_string = from_jwt.encode_with_signer(&signer)?;

            let verifier = alg.verifier_from_der(&public_key)?;
            let to_jwt = Jwt::decode_with_verifier(&jwt_string, &verifier)?;

            assert_eq!(from_jwt, to_jwt);
        }

        Ok(())
    }

    #[test]
    fn test_jwt_with_ecdsa_pem() -> Result<()> {
        let from_jwt = Jwt::new();

        for alg in &[ES256, ES384, ES512, ES256K] {
            let private_key = load_file(match alg {
                ES256 => "pem/ECDSA_P-256_pkcs8_private.pem",
                ES384 => "pem/ECDSA_P-384_pkcs8_private.pem",
                ES512 => "pem/ECDSA_P-521_pkcs8_private.pem",
                ES256K => "pem/ECDSA_secp256k1_pkcs8_private.pem",
            })?;
            let public_key = load_file(match alg {
                ES256 => "pem/ECDSA_P-256_pkcs8_public.pem",
                ES384 => "pem/ECDSA_P-384_pkcs8_public.pem",
                ES512 => "pem/ECDSA_P-521_pkcs8_public.pem",
                ES256K => "pem/ECDSA_secp256k1_pkcs8_public.pem",
            })?;

            let signer = alg.signer_from_pem(&private_key)?;
            let jwt_string = from_jwt.encode_with_signer(signer)?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            let to_jwt = Jwt::decode_with_verifier(&jwt_string, verifier)?;

            assert_eq!(from_jwt, to_jwt);
        }

        Ok(())
    }

    #[test]
    fn test_jwt_with_ecdsa_der() -> Result<()> {
        let from_jwt = Jwt::new();

        for alg in &[ES256, ES384, ES512, ES256K] {
            let private_key = load_file(match alg {
                ES256 => "der/ECDSA_P-256_pkcs8_private.der",
                ES384 => "der/ECDSA_P-384_pkcs8_private.der",
                ES512 => "der/ECDSA_P-521_pkcs8_private.der",
                ES256K => "der/ECDSA_secp256k1_pkcs8_private.der",
            })?;
            let public_key = load_file(match alg {
                ES256 => "der/ECDSA_P-256_pkcs8_public.der",
                ES384 => "der/ECDSA_P-384_pkcs8_public.der",
                ES512 => "der/ECDSA_P-521_pkcs8_public.der",
                ES256K => "der/ECDSA_secp256k1_pkcs8_public.der",
            })?;

            let signer = alg.signer_from_der(&private_key)?;
            let jwt_string = from_jwt.encode_with_signer(&signer)?;

            let verifier = alg.verifier_from_der(&public_key)?;
            let to_jwt = Jwt::decode_with_verifier(&jwt_string, verifier)?;

            assert_eq!(from_jwt, to_jwt);
        }

        Ok(())
    }
    
    #[test]
    fn test_external_jwt_verify_with_hmac() -> Result<()> {
        let jwk = Jwk::from_slice(&load_file("jwk/oct_private.jwk")?)?;

        for alg in &[HS256, HS384, HS512] {
            let verifier = alg.verifier_from_jwk(&jwk)?;
            let jwt_str = &String::from_utf8(load_file(&format!("jwt/{}.jwt", alg.name()))?)?;
            let jwt = Jwt::decode_with_verifier(&jwt_str, &verifier)?;

            assert!(matches!(jwt.subject(), Some("test")));
        }

        Ok(())
    }

    #[test]
    fn test_external_jwt_verify_with_rsa() -> Result<()> {
        let jwk = Jwk::from_slice(&load_file("jwk/RSA_public.jwk")?)?;

        for alg in &[RS256, RS384, RS512] {
            let verifier = alg.verifier_from_jwk(&jwk)?;
            let jwt_str = &String::from_utf8(load_file(&format!("jwt/{}.jwt", alg.name()))?)?;
            let jwt = Jwt::decode_with_verifier(&jwt_str, &verifier)?;

            assert!(matches!(jwt.subject(), Some("test")));
        }

        Ok(())
    }

    
    #[test]
    fn test_external_jwt_verify_with_rsapss() -> Result<()> {
        let jwk = Jwk::from_slice(&load_file("jwk/RSA_public.jwk")?)?;

        for alg in &[PS256, PS384, PS512] {
            let verifier = alg.verifier_from_jwk(&jwk)?;
            let jwt_str = &String::from_utf8(load_file(&format!("jwt/{}.jwt", alg.name()))?)?;
            let jwt = Jwt::decode_with_verifier(&jwt_str, &verifier)?;

            assert!(matches!(jwt.subject(), Some("test")));
        }

        Ok(())
    }

    #[test]
    fn test_external_jwt_verify_with_ecdsa() -> Result<()> {
        for alg in &[ES256, ES384, ES512, ES256K] {
            let jwk = Jwk::from_slice(&load_file(match alg {
                ES256 => "jwk/EC_P-256_public.jwk",
                ES384 => "jwk/EC_P-384_public.jwk",
                ES512 => "jwk/EC_P-521_public.jwk",
                ES256K => "jwk/EC_secp256k1_public.jwk",
            })?)?;
            let verifier = alg.verifier_from_jwk(&jwk)?;
            let jwt_str = &String::from_utf8(load_file(&format!("jwt/{}.jwt", alg.name()))?)?;
            let jwt = Jwt::decode_with_verifier(&jwt_str, &verifier)?;

            //assert!(matches!(jwt.subject(), Some("test")));
        }

        Ok(())
    }

    #[test]
    fn test_external_jwt_verify_with_eddsa() -> Result<()> {
        for alg in &[EDDSA] {
            let jwk = Jwk::from_slice(&load_file(match alg {
                EDDSA => "jwk/OKP_Ed25519_public.jwk",
            })?)?;
            let verifier = alg.verifier_from_jwk(&jwk)?;
            let jwt_str = &String::from_utf8(load_file(&format!("jwt/{}.jwt", alg.name()))?)?;
            let jwt = Jwt::decode_with_verifier(&jwt_str, &verifier)?;

            assert!(matches!(jwt.subject(), Some("test")));
        }

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

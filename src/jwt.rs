use std::time::{Duration, SystemTime};

use anyhow::bail;
use serde_json::map::Entry;
use serde_json::{json, Map};
use chrono::{DateTime, Utc};

use crate::jws::{JwsAlgorithm, JwsSigner, JwsVerifier };
use crate::error::JoseError;

/// Represents any valid JSON value.
///
/// See the `serde_json::value` module documentation for usage examples.
pub type Value = serde_json::Value;

/// Represents plain JWT object with header and payload.
#[derive(Debug, Eq, PartialEq)]
pub struct Jwt {
    header: Map<String, Value>,
    payload: Map<String, Value>,
}

impl Jwt {
    /// Return a new JWT object that has only a typ="JWT" header claim.
    pub fn new() -> Self {
        let mut header = Map::new();
        header.insert("typ".to_string(), json!("JWT"));

        Self {
            header,
            payload: Map::new(),
        }
    }

    /// Return a JWT object that is decoded the input with a "none" algorithm.
    ///
    /// # Arguments
    /// * `input` - JWT text.
    pub fn decode_with_none(input: &str) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let parts: Vec<&str> = input.split('.').collect();
            if parts.len() != 2 {
                bail!("JWT must be two parts separated by colon.");
            }

            let header_base64 = parts.get(0).unwrap();
            let header_json = base64::decode_config(header_base64, base64::URL_SAFE_NO_PAD)?;
            let header: Map<String, Value> = serde_json::from_slice(&header_json)?;

            let payload_base64 = parts.get(1).unwrap();
            let payload_json = base64::decode_config(payload_base64, base64::URL_SAFE_NO_PAD)?;
            let payload: Map<String, Value> = serde_json::from_slice(&payload_json)?;

            let jwt = Jwt { header, payload };

            if let Some(expected_alg) = jwt.algorithm() {
                let actual_alg = "none";
                if expected_alg != actual_alg {
                    bail!(
                        "JWT alg header parameter is mismatched: expected = {}, actual = {}",
                        expected_alg,
                        actual_alg
                    );
                }
            } else {
                bail!("JWT alg header parameter is missing.");
            }

            Ok(jwt)
        })()
        .map_err(|err| JoseError::InvalidJwtFormat(err))
    }

    /// Return a JWT Object that is decoded the input with a signing algorithm.
    ///
    /// # Arguments
    /// * `input` - JWT text.
    /// * `verifier` - A verifier of the siging algorithm.
    pub fn decode_with_verifier<T: JwsAlgorithm>(
        input: &str,
        verifier: &impl JwsVerifier<T>,
    ) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Result<Jwt, JoseError>> {
            let parts: Vec<&str> = input.split('.').collect();
            if parts.len() != 3 {
                bail!("JWT must be three parts separated by colon.");
            }

            let header_base64 = parts.get(0).unwrap();
            let header_json = base64::decode_config(header_base64, base64::URL_SAFE_NO_PAD)?;
            let header: Map<String, Value> = serde_json::from_slice(&header_json)?;

            let payload_base64 = parts.get(1).unwrap();
            let payload_json = base64::decode_config(payload_base64, base64::URL_SAFE_NO_PAD)?;
            let payload: Map<String, Value> = serde_json::from_slice(&payload_json)?;

            let jwt = Jwt { header, payload };

            if let Some(expected_alg) = jwt.algorithm() {
                let actual_alg = verifier.algorithm().name();
                if expected_alg != actual_alg {
                    bail!(
                        "JWT alg header parameter is mismatched: expected = {}, actual = {}",
                        expected_alg,
                        actual_alg
                    );
                }
            } else {
                bail!("JWT alg header parameter is missing.");
            }

            let signature_base64 = parts.get(2).unwrap();
            let signature = base64::decode_config(signature_base64, base64::URL_SAFE_NO_PAD)?;

            Ok(verifier
                .verify(
                    &[header_base64.as_bytes(), b".", payload_base64.as_bytes()],
                    &signature,
                )
                .map(|_| jwt))
        })()
        .map_err(|err| JoseError::InvalidJwtFormat(err))?
    }

    /// Return a JWT Object that is decoded the input with a signing algorithm.
    ///
    /// # Arguments
    /// * `input` - JWT text.
    /// * `verifier_selector` - A function for selecting the siging algorithm.
    pub fn decode_with_verifier_selector<'a, T, F>(
        input: &str,
        verifier_selector: F,
    ) -> Result<Self, JoseError>
    where
        T: JwsAlgorithm + 'a,
        F: FnOnce(&Jwt) -> Box<&'a dyn JwsVerifier<T>>,
    {
        (|| -> anyhow::Result<Result<Jwt, JoseError>> {
            let parts: Vec<&str> = input.split('.').collect();
            if parts.len() != 2 && parts.len() != 3 {
                bail!("JWT must be two or three parts separated by colon.");
            }

            let header_base64 = parts.get(0).unwrap();
            let header_json = base64::decode_config(header_base64, base64::URL_SAFE_NO_PAD)?;
            let header: Map<String, Value> = serde_json::from_slice(&header_json)?;

            let payload_base64 = parts.get(1).unwrap();
            let payload_json = base64::decode_config(payload_base64, base64::URL_SAFE_NO_PAD)?;
            let payload: Map<String, Value> = serde_json::from_slice(&payload_json)?;

            let jwt = Jwt { header, payload };

            let alg = match jwt.algorithm() {
                Some(alg) if alg == "none" => {
                    if parts.len() != 2 {
                        bail!("JWT must not have signature part when alg = \"none\".");
                    }
                    alg
                },
                Some(alg) => {
                    if parts.len() != 3 {
                        bail!("JWT must have signature part when alg != \"none\".");
                    }
                    alg
                },
                None => {
                    bail!("JWT alg header claim is required.");
                }
            };

            let verifier = verifier_selector(&jwt);

            let algorithm_alg = verifier.algorithm().name();
            if alg != algorithm_alg {
                bail!(
                    "JWT alg header parameter is mismatched: expected = {}, actual = {}",
                    algorithm_alg,
                    alg
                );
            }

            let signature_base64 = parts.get(2).unwrap();
            let signature = base64::decode_config(signature_base64, base64::URL_SAFE_NO_PAD)?;

            Ok(verifier
                .verify(
                    &[header_base64.as_bytes(), b".", payload_base64.as_bytes()],
                    &signature,
                )
                .map(|_| jwt))
        })()
        .map_err(|err| JoseError::InvalidJwtFormat(err))?
    }

    /// Set a value for token type header claim (typ).
    ///
    /// # Arguments
    /// * `token_type` - A token type (e.g. "JWT")
    pub fn set_token_type(&mut self, token_type: &str) -> &mut Self {
        self.header.insert("typ".to_string(), json!(token_type));
        self
    }

    /// Return a value for token type header claim (typ).
    pub fn token_type(&self) -> Option<&str> {
        match self.header.get("typ") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Return a value for algorithm header claim (alg).
    pub fn algorithm(&self) -> Option<&str> {
        match self.header.get("alg") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for content type header claim (cty).
    ///
    /// # Arguments
    /// * `content_type` - A content type (e.g. "JWT")
    pub fn set_content_type(&mut self, content_type: &str) -> &mut Self {
        self.header.insert("cty".to_string(), json!(content_type));
        self
    }

    /// Return a value for content type header claim (cty).
    pub fn content_type(&self) -> Option<&str> {
        match self.header.get("cty") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for content type header claim (kid).
    ///
    /// # Arguments
    /// * `key_id` - A key ID
    pub fn set_key_id(&mut self, key_id: &str) -> &mut Self {
        self.header.insert("kid".to_string(), json!(key_id));
        self
    }

    /// Return a value for key ID header claim (kid).
    pub fn key_id(&self) -> Option<&str> {
        match self.header.get("kid") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for a header claim of a specified key.
    ///
    /// # Arguments
    /// * `key` - A key name of a header claim
    /// * `value` - A typed value of a header claim
    pub fn set_header_claim(&mut self, key: &str, value: &Value) -> &mut Self {
        self.header.insert(key.to_string(), (*value).clone());
        self
    }

    /// Return a value for a header claim of a specified key.
    ///
    /// # Arguments
    /// * `key` - A key name of a header claim
    pub fn header_claim(&self, key: &str) -> Option<&Value> {
        self.header.get(key)
    }

    /// Unset a value for a header claim of a specified key.
    ///
    /// # Arguments
    /// * `key` - A key name of a header claim
    pub fn unset_header_claim(&mut self, key: &str) -> &mut Self{
        self.header.remove(key);
        self
    }

    /// Set a value for a issuer payload claim (iss).
    ///
    /// # Arguments
    /// * `issuer` - A issuer
    pub fn set_issuer(&mut self, issuer: &str) -> &mut Self {
        self.payload.insert("iss".to_string(), json!(issuer));
        self
    }

    /// Return a value for a issuer payload claim (iss).
    pub fn issuer(&self) -> Option<&str> {
        match self.payload.get("iss") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for a subject payload claim (sub).
    ///
    /// # Arguments
    /// * `subject` - A subject
    pub fn set_subject<'a>(&mut self, subject: &str) -> &mut Self {
        self.payload.insert("sub".to_string(), json!(subject));
        self
    }

    /// Return a value for a subject payload claim (sub).
    pub fn subject(&self) -> Option<&str> {
        match self.payload.get("sub") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for a audience payload claim (aud).
    ///
    /// # Arguments
    /// * `audience` - A audience
    pub fn set_audience<'a>(&mut self, audience: &str) -> &mut Self {
        self.payload.insert("aud".to_string(), json!(audience));
        self
    }

    /// Add a value for a audience payload claim (aud).
    ///
    /// # Arguments
    /// * `audience` - A audience
    pub fn add_audience<'a>(&mut self, audience: &str) -> &mut Self {
        match self.payload.entry("aud") {
            Entry::Vacant(entry) => {
                entry.insert(json!(audience));
            }
            Entry::Occupied(mut entry) => match entry.get_mut() {
                Value::Array(vals) => {
                    vals.push(json!(audience));
                }
                Value::String(val) => {
                    let mut vals = Vec::new();
                    vals.push(json!(val));
                    entry.insert(json!(vals));
                }
                _ => {
                    entry.insert(json!(audience));
                }
            },
        }
        self
    }

    /// Set values for a audience payload claim (aud).
    ///
    /// # Arguments
    /// * `audiences` - A list of audiences
    pub fn set_audiences(&mut self, audiences: Vec<&str>) -> &mut Self {
        match self.payload.entry("aud") {
            Entry::Vacant(entry) => {
                let mut list = Vec::new();
                for audience in audiences {
                    list.push(json!(audience));
                }
                entry.insert(json!(list));
            }
            Entry::Occupied(mut entry) => match entry.get_mut() {
                Value::Array(vals) => {
                    for audience in audiences {
                        vals.push(json!(audience.to_string()));
                    }
                }
                Value::String(val) => {
                    let mut vals = Vec::new();
                    vals.push(json!(val.to_string()));
                    for audience in audiences {
                        vals.push(json!(audience.to_string()));
                    }
                    entry.insert(json!(vals));
                }
                _ => {
                    let mut list = Vec::new();
                    for audience in audiences {
                        list.push(json!(audience.to_string()));
                    }
                    entry.insert(json!(list));
                }
            },
        }
        self
    }

    /// Return a value for a audience payload claim (sub).
    pub fn audience(&self) -> Option<Vec<&str>> {
        match self.payload.get("aud") {
            Some(Value::String(str_val)) => {
                let mut list = Vec::new();
                list.push(str_val.as_str());
                Some(list)
            }
            Some(Value::Array(vals)) => {
                let mut list = Vec::new();
                for val in vals {
                    if let Value::String(str_val) = val {
                        list.push(str_val.as_str());
                    }
                }
                Some(list)
            }
            _ => None,
        }
    }

    /// Set a system time for a expires at payload claim (exp).
    ///
    /// # Arguments
    /// * `expires_at` - The expiration time on or after which the JWT must not be accepted for processing.
    pub fn set_expires_at(&mut self, expires_at: &SystemTime) -> &mut Self {
        self.payload.insert(
            "exp".to_string(),
            json!(expires_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()),
        );
        self
    }

    /// Return a system time for a expires at payload claim (exp).
    pub fn expires_at(&self) -> Option<SystemTime> {
        match self.payload.get("exp") {
            Some(Value::Number(val)) => match val.as_u64() {
                Some(val) => Some(SystemTime::UNIX_EPOCH + Duration::from_secs(val)),
                _ => None,
            },
            _ => None,
        }
    }

    /// Set a system time for a not before payload claim (nbf).
    ///
    /// # Arguments
    /// * `not_before` - The time before which the JWT must not be accepted for processing.
    pub fn set_not_before(&mut self, not_before: &SystemTime) -> &mut Self {
        self.payload.insert(
            "nbf".to_string(),
            json!(not_before
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()),
        );
        self
    }

    /// Return a system time for a not before payload claim (nbf).
    pub fn not_before(&self) -> Option<SystemTime> {
        match self.payload.get("nbf") {
            Some(Value::Number(val)) => match val.as_u64() {
                Some(val) => Some(SystemTime::UNIX_EPOCH + Duration::from_secs(val)),
                _ => None,
            },
            _ => None,
        }
    }

    /// Set a time for a issued at payload claim (iat).
    ///
    /// # Arguments
    /// * `issued_at` - The time at which the JWT was issued.
    pub fn set_issued_at(&mut self, issued_at: &SystemTime) -> &mut Self {
        self.payload.insert(
            "iat".to_string(),
            json!(issued_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()),
        );
        self
    }

    /// Return a time for a issued at payload claim (iat).
    pub fn issued_at(&self) -> Option<SystemTime> {
        match self.payload.get("iat") {
            Some(Value::Number(val)) => match val.as_u64() {
                Some(val) => Some(SystemTime::UNIX_EPOCH + Duration::from_secs(val)),
                _ => None,
            },
            _ => None,
        }
    }

    /// Set a value for a jwt id payload claim (jti).
    ///
    /// # Arguments
    /// * `jwt_id` - A jwt id
    pub fn set_jwt_id(&mut self, jwt_id: &str) -> &mut Self {
        self.payload.insert("jti".to_string(), json!(jwt_id));
        self
    }

    /// Return a value for a jwt id payload claim (jti).
    pub fn jwt_id(&self) -> Option<&str> {
        match self.payload.get("jti") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for a payload claim of a specified key.
    ///
    /// # Arguments
    /// * `key` - A key name of a payload claim
    /// * `value` - A typed value of a payload claim
    pub fn set_payload_claim(&mut self, key: &str, value: &Value) -> &mut Self {
        self.payload.insert(key.to_string(), (*value).clone());
        self
    }

    /// Return a value for a payload claim of a specified key.
    ///
    /// # Arguments
    /// * `key` - A key name of a payload claim
    pub fn payload_claim(&self, key: &str) -> Option<&Value> {
        self.payload.get(key)
    }

    /// Unset a value for a payload claim of a specified key.
    ///
    /// # Arguments
    /// * `key` - A key name of a payload claim
    pub fn unset_payload_claim(&mut self, key: &str) -> &mut Self {
        self.payload.remove(key);
        self
    }

    /// Return a JWT text that is decoded with a "none" algorithm.
    pub fn encode_with_none(&self) -> Result<String, JoseError> {
        let alg_key = "alg".to_string();
        let mut new_header;
        let header = match &self.header.get(&alg_key) {
            Some(Value::String(alg)) if alg == "none" => &self.header,
            _ => {
                new_header = self.header.clone();
                new_header.insert("alg".to_string(), json!("none"));
                &new_header
            }
        };

        let header_json = serde_json::to_string(header).unwrap();
        let header_base64 = base64::encode_config(header_json, base64::URL_SAFE_NO_PAD);

        let payload_json = serde_json::to_string(&self.payload).unwrap();
        let payload_base64 = base64::encode_config(payload_json, base64::URL_SAFE_NO_PAD);

        Ok(format!("{}.{}", header_base64, payload_base64))
    }

    /// Return a JWT text that is encoded with a signing algorithm.
    ///
    /// # Arguments
    ///
    /// * `signer` - A signer of the siging algorithm.
    pub fn encode_with_signer<T: JwsAlgorithm>(
        &self,
        signer: &impl JwsSigner<T>,
    ) -> Result<String, JoseError> {
        let name = signer.algorithm().name();

        let mut header = self.header.clone();
        header.insert("alg".to_string(), Value::String(name.to_string()));

        let header_json = serde_json::to_string(&header).unwrap();
        let header_base64 = base64::encode_config(header_json, base64::URL_SAFE_NO_PAD);

        let payload_json = serde_json::to_string(&self.payload).unwrap();
        let payload_base64 = base64::encode_config(payload_json, base64::URL_SAFE_NO_PAD);

        let signature =
            signer.sign(&[header_base64.as_bytes(), b".", payload_base64.as_bytes()])?;

        let signature_base64 = base64::encode_config(signature, base64::URL_SAFE_NO_PAD);
        Ok(format!(
            "{}.{}.{}",
            header_base64, payload_base64, signature_base64
        ))
    }
}

/// Represents JWT validator.
#[derive(Debug, Eq, PartialEq)]
pub struct JwtValidator {
    base_time: Option<SystemTime>,
    min_issued_time: Option<SystemTime>,
    max_issued_time: Option<SystemTime>,
    payload: Map<String, Value>,
}

impl JwtValidator {
    /// Set a base time for a time related claim (exp, nbf) validation.
    ///
    /// # Arguments
    /// * `base_time` - A min time
    pub fn set_base_time(&mut self, base_time: SystemTime) -> &mut Self {
        self.base_time = Some(base_time);
        self
    }

    /// Return a base time for a time related claim (exp, nbf) validation.
    pub fn base_time(&self) -> Option<SystemTime> {
        self.base_time
    }

    /// Set a minimum time for a issued at payload claim (iat) validation.
    ///
    /// # Arguments
    /// * `min_issued_time` - The minimum time at which the JWT was issued.
    pub fn set_min_issued_time(&mut self, min_issued_time: &SystemTime) -> &mut Self {
        self.min_issued_time = Some(*min_issued_time);
        self
    }

    /// Return a minimum time for a issued at payload claim (iat).
    pub fn min_issued_time(&self) -> Option<SystemTime> {
        self.min_issued_time
    }
    
    /// Set a maximum time for a issued at payload claim (iat) validation.
    ///
    /// # Arguments
    /// * `max_issued_time` - A maximum time at which the JWT was issued.
    pub fn set_max_issued_time(&mut self, max_issued_time: &SystemTime) -> &mut Self {
        self.max_issued_time = Some(*max_issued_time);
        self
    }

    /// Return a maximum time for a issued at payload claim (iat).
    pub fn max_issued_time(&self) -> Option<SystemTime> {
        self.max_issued_time
    }

    /// Set a value for a issuer payload claim (iss) validation.
    ///
    /// # Arguments
    /// * `issuer` - A issuer
    pub fn set_issuer(&mut self, issuer: &str) -> &mut Self {
        self.payload.insert("iss".to_string(), json!(issuer));
        self
    }

    /// Return a value for a issuer payload claim (iss) validation.
    pub fn issuer(&self) -> Option<&str> {
        match self.payload.get("iss") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for a subject payload claim (sub) validation.
    ///
    /// # Arguments
    /// * `subject` - A subject
    pub fn set_subject<'a>(&mut self, subject: &str) -> &mut Self {
        self.payload.insert("sub".to_string(), json!(subject));
        self
    }

    /// Return a value for a subject payload claim (sub) validation.
    pub fn subject(&self) -> Option<&str> {
        match self.payload.get("sub") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for a audience payload claim (aud) validation.
    ///
    /// # Arguments
    /// * `audience` - A audience
    pub fn set_audience<'a>(&mut self, audience: &str) -> &mut Self {
        self.payload.insert("aud".to_string(), json!(audience));
        self
    }

    /// Add a value for a audience payload claim (aud) validation.
    ///
    /// # Arguments
    /// * `audience` - A audience
    pub fn add_audience<'a>(&mut self, audience: &str) -> &mut Self {
        match self.payload.entry("aud") {
            Entry::Vacant(entry) => {
                entry.insert(json!(audience));
            }
            Entry::Occupied(mut entry) => match entry.get_mut() {
                Value::Array(vals) => {
                    vals.push(json!(audience));
                }
                Value::String(val) => {
                    let mut vals = Vec::new();
                    vals.push(json!(val));
                    entry.insert(json!(vals));
                }
                _ => {
                    entry.insert(json!(audience));
                }
            },
        }
        self
    }

    /// Set values for a audience payload claim (aud) validation.
    ///
    /// # Arguments
    /// * `audiences` - A list of audiences
    pub fn set_audiences(&mut self, audiences: Vec<&str>) -> &mut Self {
        match self.payload.entry("aud") {
            Entry::Vacant(entry) => {
                let mut list = Vec::new();
                for audience in audiences {
                    list.push(json!(audience));
                }
                entry.insert(json!(list));
            }
            Entry::Occupied(mut entry) => match entry.get_mut() {
                Value::Array(vals) => {
                    for audience in audiences {
                        vals.push(json!(audience.to_string()));
                    }
                }
                Value::String(val) => {
                    let mut vals = Vec::new();
                    vals.push(json!(val.to_string()));
                    for audience in audiences {
                        vals.push(json!(audience.to_string()));
                    }
                    entry.insert(json!(vals));
                }
                _ => {
                    let mut list = Vec::new();
                    for audience in audiences {
                        list.push(json!(audience.to_string()));
                    }
                    entry.insert(json!(list));
                }
            },
        }
        self
    }

    /// Return a value for a audience payload claim (sub) validation.
    pub fn audience(&self) -> Option<Vec<&str>> {
        match self.payload.get("aud") {
            Some(Value::String(str_val)) => {
                let mut list = Vec::new();
                list.push(str_val.as_str());
                Some(list)
            }
            Some(Value::Array(vals)) => {
                let mut list = Vec::new();
                for val in vals {
                    if let Value::String(str_val) = val {
                        list.push(str_val.as_str());
                    }
                }
                Some(list)
            }
            _ => None,
        }
    }
    
    /// Set a value for a jwt id payload claim (jti) validation.
    ///
    /// # Arguments
    /// * `jwt_id` - A jwt id
    pub fn set_jwt_id(&mut self, jwt_id: &str) -> &mut Self {
        self.payload.insert("jti".to_string(), json!(jwt_id));
        self
    }

    /// Return a value for a jwt id payload claim (jti) validation.
    pub fn jwt_id(&self) -> Option<&str> {
        match self.payload.get("jti") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for a payload claim of a specified key.
    ///
    /// # Arguments
    /// * `key` - A key name of a payload claim
    /// * `value` - A typed value of a payload claim
    pub fn set_payload_claim(&mut self, key: &str, value: &Value) -> &mut Self {
        self.payload.insert(key.to_string(), (*value).clone());
        self
    }

    /// Return a value for a payload claim of a specified key.
    ///
    /// # Arguments
    /// * `key` - A key name of a payload claim
    pub fn payload_claim(&self, key: &str) -> Option<&Value> {
        self.payload.get(key)
    }

    /// Validate decoded JWT claims.
    ///
    /// # Arguments
    /// * `jwt` - A decoded JWT
    pub fn validate(&self, jwt: &Jwt) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            let now = SystemTime::now();
            let current_time = self.base_time().unwrap_or(now);
            let min_issued_time = self.min_issued_time().unwrap_or(SystemTime::UNIX_EPOCH);
            let max_issued_time = self.max_issued_time().unwrap_or(now);

            if let Some(not_before) = jwt.not_before() {
                if not_before > current_time {
                    bail!("The token is not yet valid: {}", DateTime::<Utc>::from(not_before));
                }
            }

            if let Some(expires_at) = jwt.expires_at() {
                if expires_at <= current_time {
                    bail!("The token has expired: {}", DateTime::<Utc>::from(expires_at));
                }
            }

            if let Some(issued_at) = jwt.issued_at() {
                if issued_at < min_issued_time {
                    bail!("The issued time is too old: {}", DateTime::<Utc>::from(issued_at));
                }

                if issued_at < max_issued_time {
                    bail!("The issued time is too new: {}", DateTime::<Utc>::from(issued_at));
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
        .map_err(|err| JoseError::InvalidClaim(err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Result;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;

    use crate::jws::{HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512};

    #[test]
    fn test_jwt_with_none() -> Result<()> {
        let from_jwt = Jwt::new();

        let jwt_string = from_jwt.encode_with_none()?;
        let mut to_jwt = Jwt::decode_with_none(&jwt_string)?;
        to_jwt.unset_header_claim("alg");

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

            let mut to_jwt = Jwt::decode_with_verifier(&jwt_string, &signer)?;
            to_jwt.unset_header_claim("alg");

            assert_eq!(from_jwt, to_jwt);
        }

        Ok(())
    }

    #[test]
    fn test_jwt_with_rsa_pem() -> Result<()> {
        let from_jwt = Jwt::new();

        for alg in &[RS256, RS384, RS512] {
            let private_key = load_file("pem/rsa_2048_pkcs8_private.pem")?;
            let public_key = load_file("pem/rsa_2048_pkcs8_public.pem")?;

            let signer = alg.signer_from_pem(&private_key)?;
            let jwt_string = from_jwt.encode_with_signer(&signer)?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            let mut to_jwt = Jwt::decode_with_verifier(&jwt_string, &verifier)?;
            to_jwt.unset_header_claim("alg");

            assert_eq!(from_jwt, to_jwt);
        }

        Ok(())
    }
    
    #[test]
    fn test_jwt_with_rsapss_pem() -> Result<()> {
        let from_jwt = Jwt::new();

        for alg in &[PS256, PS384, PS512] {
            let private_key = load_file(match alg.name() {
                "PS256" => "pem/rsapss_2048_sha256_pkcs8_private.pem",
                "PS384" => "pem/rsapss_2048_sha384_pkcs8_private.pem",
                "PS512" => "pem/rsapss_2048_sha512_pkcs8_private.pem",
                _ => unreachable!()
            })?;
            let public_key = load_file(match alg.name() {
                "PS256" => "pem/rsapss_2048_sha256_pkcs8_public.pem",
                "PS384" => "pem/rsapss_2048_sha384_pkcs8_public.pem",
                "PS512" => "pem/rsapss_2048_sha512_pkcs8_public.pem",
                _ => unreachable!()
            })?;

            let signer = alg.signer_from_pem(&private_key)?;
            let jwt_string = from_jwt.encode_with_signer(&signer)?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            let mut to_jwt = Jwt::decode_with_verifier(&jwt_string, &verifier)?;
            to_jwt.unset_header_claim("alg");

            assert_eq!(from_jwt, to_jwt);
        }

        Ok(())
    }

    #[test]
    fn test_jwt_with_rsa_der() -> Result<()> {
        let from_jwt = Jwt::new();

        for alg in &[RS256, RS384, RS512] {
            let private_key = load_file("der/rsa_2048_pkcs8_private.der")?;
            let public_key = load_file("der/rsa_2048_pkcs8_public.der")?;

            let signer = alg.signer_from_der(&private_key)?;
            let jwt_string = from_jwt.encode_with_signer(&signer)?;

            let verifier = alg.verifier_from_der(&public_key)?;
            let mut to_jwt = Jwt::decode_with_verifier(&jwt_string, &verifier)?;
            to_jwt.unset_header_claim("alg");

            assert_eq!(from_jwt, to_jwt);
        }

        Ok(())
    }

    #[test]
    fn test_jwt_with_ecdsa_pem() -> Result<()> {
        let from_jwt = Jwt::new();

        for alg in &[ES256, ES384, ES512] {
            let private_key = load_file(match alg.name() {
                "ES256" => "pem/ecdsa_p256_pkcs8_private.pem",
                "ES384" => "pem/ecdsa_p384_pkcs8_private.pem",
                "ES512" => "pem/ecdsa_p521_pkcs8_private.pem",
                _ => unreachable!()
            })?;
            let public_key = load_file(match alg.name() {
                "ES256" => "pem/ecdsa_p256_pkcs8_public.pem",
                "ES384" => "pem/ecdsa_p384_pkcs8_public.pem",
                "ES512" => "pem/ecdsa_p521_pkcs8_public.pem",
                _ => unreachable!()
            })?;

            let signer = alg.signer_from_pem(&private_key)?;
            let jwt_string = from_jwt.encode_with_signer(&signer)?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            let mut to_jwt = Jwt::decode_with_verifier(&jwt_string, &verifier)?;
            to_jwt.unset_header_claim("alg");

            assert_eq!(from_jwt, to_jwt);
        }

        Ok(())
    }

    #[test]
    fn test_jwt_with_ecdsa_der() -> Result<()> {
        let from_jwt = Jwt::new();

        for alg in &[ES256, ES384, ES512] {
            let private_key = load_file(match alg.name() {
                "ES256" => "der/ecdsa_p256_pkcs8_private.der",
                "ES384" => "der/ecdsa_p384_pkcs8_private.der",
                "ES512" => "der/ecdsa_p521_pkcs8_private.der",
                _ => unreachable!()
            })?;
            let public_key = load_file(match alg.name() {
                "ES256" => "der/ecdsa_p256_pkcs8_public.der",
                "ES384" => "der/ecdsa_p384_pkcs8_public.der",
                "ES512" => "der/ecdsa_p521_pkcs8_public.der",
                _ => unreachable!()
            })?;

            let signer = alg.signer_from_der(&private_key)?;
            let jwt_string = from_jwt.encode_with_signer(&signer)?;

            let verifier = alg.verifier_from_der(&public_key)?;
            let mut to_jwt = Jwt::decode_with_verifier(&jwt_string, &verifier)?;
            to_jwt.unset_header_claim("alg");

            assert_eq!(from_jwt, to_jwt);
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

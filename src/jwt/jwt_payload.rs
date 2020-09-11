use std::collections::HashMap;
use std::convert::Into;
use std::fmt::Display;
use std::time::{Duration, SystemTime};

use anyhow::bail;
use serde_json::{Map, Number, Value};

use crate::jose::JoseError;
use crate::util::SourceValue;

#[derive(Debug, Eq, PartialEq, Clone, Default)]
pub struct JwtPayload {
    claims: Map<String, Value>,
    sources: HashMap<String, SourceValue>,
}

impl JwtPayload {
    /// Return a new JWT payload
    pub fn new() -> Self {
        Self {
            claims: Map::new(),
            sources: HashMap::new(),
        }
    }

    /// Return the JWT payload from map.
    ///
    /// # Arguments
    ///
    /// * `claims` - JWT payload claims.
    pub fn from_map(claims: Map<String, Value>) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let mut sources = HashMap::new();
            for (key, value) in &claims {
                match key.as_ref() {
                    "iss" | "sub" | "jti" => match value {
                        Value::String(_) => {}
                        _ => bail!("The JWT {} payload claim must be a string.", key),
                    },
                    "aud" => match value {
                        Value::String(_) => {}
                        Value::Array(vals) => {
                            let mut vec = Vec::with_capacity(vals.len());
                            for val in vals {
                                match val {
                                    Value::String(val) => vec.push(val.to_string()),
                                    _ => bail!(
                                        "An element of JWT {} payload claim must be a string.",
                                        key
                                    ),
                                }
                            }
                            sources.insert(key.clone(), SourceValue::StringArray(vec));
                        }
                        _ => bail!("The JWT {} payload claim must be a string or array.", key),
                    },
                    "exp" | "nbf" | "iat" => match value {
                        Value::Number(val) => match val.as_u64() {
                            Some(val) => {
                                let val = SystemTime::UNIX_EPOCH + Duration::from_secs(val);
                                sources.insert(key.clone(), SourceValue::SystemTime(val));
                            }
                            None => bail!(
                                "The JWT {} payload claim must be a positive integer within 64bit.",
                                key
                            ),
                        },
                        _ => bail!("The JWT {} payload claim must be a string type.", key),
                    },
                    _ => {}
                }
            }

            Ok(Self { claims, sources })
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err),
        })
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

    /// Set a system time for expires at payload claim (exp).
    ///
    /// # Arguments
    ///
    /// * `value` - A expiration time on or after which the JWT must not be accepted for processing.
    pub fn set_expires_at(&mut self, value: SystemTime) {
        let key = "exp".to_string();
        let val = Number::from(
            value
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        self.claims.insert(key.clone(), Value::Number(val));
        self.sources.insert(key, SourceValue::SystemTime(value));
    }

    /// Return the system time for expires at payload claim (exp).
    pub fn expires_at(&self) -> Option<&SystemTime> {
        match self.sources.get("exp") {
            Some(SourceValue::SystemTime(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    /// Set a system time for not before payload claim (nbf).
    ///
    /// # Arguments
    ///
    /// * `value` - A time before which the JWT must not be accepted for processing.
    pub fn set_not_before(&mut self, value: SystemTime) {
        let key = "nbf".to_string();
        let val = Number::from(
            value
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        self.claims.insert(key.clone(), Value::Number(val));
        self.sources.insert(key, SourceValue::SystemTime(value));
    }

    /// Return the system time for not before payload claim (nbf).
    pub fn not_before(&self) -> Option<&SystemTime> {
        match self.sources.get("nbf") {
            Some(SourceValue::SystemTime(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    /// Set a time for issued at payload claim (iat).
    ///
    /// # Arguments
    ///
    /// * `value` - a time at which the JWT was issued.
    pub fn set_issued_at(&mut self, value: SystemTime) {
        let key = "iat".to_string();
        let val = Number::from(
            value
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        self.claims.insert(key.clone(), Value::Number(val));
        self.sources.insert(key, SourceValue::SystemTime(value));
    }

    /// Return the time for a issued at payload claim (iat).
    pub fn issued_at(&self) -> Option<&SystemTime> {
        match self.sources.get("iat") {
            Some(SourceValue::SystemTime(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    /// Set a value for JWT ID payload claim (jti).
    ///
    /// # Arguments
    ///
    /// * `value` - a JWT ID
    pub fn set_jwt_id(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.claims.insert("jti".to_string(), Value::String(value));
    }

    /// Return the value for JWT ID payload claim (jti).
    pub fn jwt_id(&self) -> Option<&str> {
        match self.claims.get("jti") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for payload claim of a specified key.
    ///
    /// # Arguments
    ///
    /// * `key` - a key name of payload claim
    /// * `value` - a typed value of payload claim
    pub fn set_claim(&mut self, key: &str, value: Option<Value>) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            match key {
                "iss" | "sub" | "jti" => match &value {
                    Some(Value::String(_)) => {
                        self.claims.insert(key.to_string(), value.unwrap());
                    }
                    None => {
                        self.claims.remove(key);
                    }
                    _ => bail!("The JWT {} payload claim must be a string.", key),
                },
                "aud" => match &value {
                    Some(Value::String(_)) => {
                        let key = key.to_string();
                        self.sources.remove(&key);
                        self.claims.insert(key, value.unwrap());
                    }
                    Some(Value::Array(vals)) => {
                        let key = key.to_string();
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
                        self.sources
                            .insert(key.clone(), SourceValue::StringArray(vec));
                        self.claims.insert(key, value.unwrap());
                    }
                    None => {
                        self.sources.remove(key);
                        self.claims.remove(key);
                    }
                    _ => bail!("The JWT {} payload claim must be a string or array.", key),
                },
                "exp" | "nbf" | "iat" => match &value {
                    Some(Value::Number(val)) => match val.as_u64() {
                        Some(val) => {
                            let key = key.to_string();
                            let val = SystemTime::UNIX_EPOCH + Duration::from_secs(val);
                            self.sources
                                .insert(key.clone(), SourceValue::SystemTime(val));
                            self.claims.insert(key, value.unwrap());
                        }
                        None => bail!(
                            "The JWT {} payload claim must be a positive integer within 64bit.",
                            key
                        ),
                    },
                    None => {
                        self.sources.remove(key);
                        self.claims.remove(key);
                    }
                    _ => bail!("The JWT {} header claim must be a string.", key),
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

    /// Return a value for payload claim of a specified key.
    ///
    /// # Arguments
    ///
    /// * `key` - a key name of payload claim
    pub fn claim(&self, key: &str) -> Option<&Value> {
        self.claims.get(key)
    }

    /// Return values for payload claims set
    pub fn claims_set(&self) -> &Map<String, Value> {
        &self.claims
    }
}

impl AsRef<Map<String, Value>> for JwtPayload {
    fn as_ref(&self) -> &Map<String, Value> {
        &self.claims
    }
}

impl Into<Map<String, Value>> for JwtPayload {
    fn into(self) -> Map<String, Value> {
        self.claims
    }
}

impl Display for JwtPayload {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let val = serde_json::to_string(self.claims_set()).map_err(|_e| std::fmt::Error {})?;
        fmt.write_str(&val)
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use anyhow::Result;
    use serde_json::json;

    use super::JwtPayload;

    #[test]
    fn test_new_payload() -> Result<()> {
        let mut payload = JwtPayload::new();
        payload.set_issuer("iss");
        payload.set_subject("sub");
        payload.set_audience(vec!["aud0", "aud1"]);
        payload.set_expires_at(SystemTime::UNIX_EPOCH);
        payload.set_not_before(SystemTime::UNIX_EPOCH);
        payload.set_issued_at(SystemTime::UNIX_EPOCH);
        payload.set_jwt_id("jti");
        payload.set_claim("payload_claim", Some(json!("payload_claim")))?;

        assert!(matches!(payload.issuer(), Some("iss")));
        assert!(matches!(payload.subject(), Some("sub")));
        assert!(matches!(payload.audience(), Some(vals) if vals == &vec!["aud0", "aud1"]));
        assert!(matches!(payload.expires_at(), Some(val) if val == &SystemTime::UNIX_EPOCH));
        assert!(matches!(payload.not_before(), Some(val) if val == &SystemTime::UNIX_EPOCH));
        assert!(matches!(payload.issued_at(), Some(val) if val == &SystemTime::UNIX_EPOCH));
        assert!(matches!(payload.jwt_id(), Some("jti")));
        assert!(
            matches!(payload.claim("payload_claim"), Some(val) if val == &json!("payload_claim"))
        );

        Ok(())
    }
}

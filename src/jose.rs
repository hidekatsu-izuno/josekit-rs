mod error;

use serde_json::{Map, Value};
use std::fmt::Display;

pub use crate::jose::error::JoseError;

pub trait JoseHeader: Display + Into<Map<String, Value>> + Send + Sync {
    /// Return a new header instance from json style header.
    ///
    /// # Arguments
    ///
    /// * `value` - The json style header claims
    fn from_slice(value: &[u8]) -> Result<Self, JoseError> {
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
    fn from_map(claims: Map<String, Value>) -> Result<Self, JoseError>;

    /// Return the value for algorithm header claim (alg).
    fn algorithm(&self) -> Option<&str> {
        match self.claims_set().get("alg") {
            Some(Value::String(val)) => Some(&val),
            _ => None,
        }
    }

    /// Return the value for header claim of a specified key.
    ///
    /// # Arguments
    ///
    /// * `key` - a key name of header claim
    fn claim(&self, key: &str) -> Option<&Value> {
        self.claims_set().get(key)
    }

    /// Return values for header claims set
    fn claims_set(&self) -> &Map<String, Value>;

    /// Set a value for header claim of a specified key.
    ///
    /// # Arguments
    ///
    /// * `key` - a key name of header claim
    /// * `value` - a typed value of header claim
    fn set_claim(&mut self, key: &str, value: Option<Value>) -> Result<(), JoseError>;
}

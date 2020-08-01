use serde_json::{Map, Value};
use std::fmt::Display;

use crate::error::JoseError;

pub trait JoseHeader: Clone + Display {
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
    /// * `key` - a key name of header claim
    fn claim(&self, key: &str) -> Option<&Value> {
        self.claims_set().get(key)
    }

    /// Return values for header claims set
    fn claims_set(&self) -> &Map<String, Value>;

    /// Set a value for header claim of a specified key.
    ///
    /// # Arguments
    /// * `key` - a key name of header claim
    /// * `value` - a typed value of header claim
    fn set_claim(&mut self, key: &str, value: Option<Value>) -> Result<(), JoseError>;
}

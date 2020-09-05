mod error;

use serde_json::{Map, Value};
use std::fmt::Display;

pub use crate::jose::error::JoseError;

pub trait JoseHeader: Display + Send + Sync {
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

    fn box_clone(&self) -> Box<dyn JoseHeader>;
}

impl Clone for Box<dyn JoseHeader> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

use std::fmt::Display;

use serde_json::{Map, Value};

pub trait JoseHeader: Display + Send + Sync {
    // Return claim count.
    fn len(&self) -> usize;

    /// Return the value for algorithm header claim (alg).
    fn algorithm(&self) -> Option<&str> {
        match self.claim("alg") {
            Some(Value::String(val)) => Some(&val),
            _ => None,
        }
    }

    /// Return the value for header claim of a specified key.
    ///
    /// # Arguments
    ///
    /// * `key` - a key name of header claim
    fn claim(&self, key: &str) -> Option<&Value>;

    fn box_clone(&self) -> Box<dyn JoseHeader>;
}

impl Clone for Box<dyn JoseHeader> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

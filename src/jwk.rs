use serde::{Deserialize, Serialize};
use serde_json::map::Entry;
use serde_json::{json, Map, Value};
use std::io::Read;
use std::string::ToString;

use crate::error::JoseError;

/// Represents JWK object.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Jwk {
    #[serde(flatten)]
    params: Map<String, Value>,
}

impl Jwk {
    pub fn new(key_type: &str) -> Self {
        let mut params = Map::new();
        params.insert("kty".to_string(), json!(key_type));
        Self { params }
    }

    pub fn from_map(map: Map<String, Value>) -> Self {
        let mut params = Map::new();
        //TODO
        Self { params }
    }

    pub fn from_reader(input: &mut dyn Read) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let jwk: Self = serde_json::from_reader(input)?;
            Ok(jwk)
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn from_slice(input: impl AsRef<[u8]>) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let jwk: Self = serde_json::from_slice(input.as_ref())?;
            Ok(jwk)
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Set a value for a key type parameter (kty).
    ///
    /// # Arguments
    /// * `value` - A key type
    pub fn set_key_type(&mut self, value: String) {
        self.params.insert("kty".to_string(), json!(value));
    }

    /// Return a value for a key type parameter (kty).
    pub fn key_type(&self) -> &str {
        match self.params.get("kty") {
            Some(Value::String(val)) => val,
            _ => panic!("A parameter kty is required."),
        }
    }

    /// Set a value for a key use parameter (use).
    ///
    /// # Arguments
    /// * `value` - A key use
    pub fn set_key_use(&mut self, value: Option<String>) {
        match value {
            Some(val) => {
                self.params.insert("use".to_string(), json!(val));
            }
            None => {
                self.params.remove("use");
            }
        }
    }

    /// Return a value for a key use parameter (use).
    pub fn key_use(&self) -> Option<&str> {
        match self.params.get("use") {
            Some(Value::String(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    /// Push a value for a key operations parameter (key_ops).
    ///
    /// # Arguments
    /// * `value` - A key operation
    pub fn push_key_operation(&mut self, value: String) {
        match self.params.entry("key_ops") {
            Entry::Vacant(entry) => {
                let mut vec = Vec::new();
                vec.push(json!(value));
                entry.insert(json!(vec));
            }
            Entry::Occupied(mut entry) => match entry.get_mut() {
                Value::Array(vals) => {
                    vals.push(json!(value));
                }
                _ => unreachable!(),
            },
        }
    }

    /// Set values for a key operations parameter (key_ops).
    ///
    /// # Arguments
    /// * `values` - key operations
    pub fn set_key_operations(&mut self, values: Option<Vec<String>>) {
        match values {
            Some(vals) => {
                self.params.insert("key_ops".to_string(), json!(vals));
            }
            None => {
                self.params.remove("key_ops");
            }
        }
    }

    /// Return values for a key operations parameter (key_ops).
    pub fn key_operations(&self) -> Option<Vec<&str>> {
        match self.params.get("key_ops") {
            Some(Value::Array(vals)) => {
                let mut vec = Vec::with_capacity(vals.len());
                for val in vals {
                    match val {
                        Value::String(val) => vec.push(val.as_ref()),
                        _ => unreachable!(),
                    }
                }
                Some(vec)
            }
            None => None,
            _ => unreachable!(),
        }
    }

    /// Set a value for a algorithm parameter (alg).
    ///
    /// # Arguments
    /// * `value` - A algorithm
    pub fn set_algorithm(&mut self, value: Option<String>) {
        match value {
            Some(val) => {
                self.params.insert("alg".to_string(), json!(val));
            }
            None => {
                self.params.remove("alg");
            }
        }
    }

    /// Return a value for a algorithm parameter (alg).
    pub fn algorithm(&self) -> Option<&str> {
        match self.params.get("alg") {
            Some(Value::String(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    /// Set a value for a key ID parameter (kid).
    ///
    /// # Arguments
    /// * `value` - A key ID
    pub fn set_key_id(&mut self, value: Option<String>) {
        match value {
            Some(val) => {
                self.params.insert("kid".to_string(), json!(val));
            }
            None => {
                self.params.remove("kid");
            }
        }
    }

    /// Return a value for a key ID parameter (kid).
    pub fn key_id(&self) -> Option<&str> {
        match self.params.get("kid") {
            Some(Value::String(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    /// Set a value for a x509 url parameter (x5u).
    ///
    /// # Arguments
    /// * `value` - A x509 url
    pub fn set_x509_url(&mut self, value: Option<String>) {
        match value {
            Some(val) => {
                self.params.insert("x5u".to_string(), json!(val));
            }
            None => {
                self.params.remove("x5u");
            }
        }
    }

    /// Return a value for a x509 url parameter (x5u).
    pub fn x509_url(&self) -> Option<&str> {
        match self.params.get("x5u") {
            Some(Value::String(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    /// Push a value for a X.509 certificate chain parameter (x5c).
    ///
    /// # Arguments
    /// * `value` - A X.509 certificate
    pub fn push_x509_certificate(&mut self, value: String) {
        match self.params.entry("x5c") {
            Entry::Vacant(entry) => {
                let mut vec = Vec::new();
                vec.push(json!(value));
                entry.insert(Value::Array(vec));
            }
            Entry::Occupied(mut entry) => match entry.get_mut() {
                Value::Array(vals) => {
                    vals.push(json!(value));
                }
                _ => unreachable!(),
            },
        }
    }

    /// Set values for a X.509 certificate chain parameter (x5c).
    ///
    /// # Arguments
    /// * `values` - X.509 certificate chain
    pub fn set_x509_certificate_chain(&mut self, values: Option<Vec<String>>) {
        match values {
            Some(vals) => {
                self.params.insert("x5c".to_string(), json!(vals));
            }
            None => {
                self.params.remove("x5c");
            }
        }
    }

    /// Return values for a X.509 certificate chain parameter (x5c).
    pub fn x509_certificate_chain(&self) -> Option<Vec<&str>> {
        match self.params.get("x5c") {
            Some(Value::Array(vals)) => {
                let mut vec = Vec::with_capacity(vals.len());
                for val in vals {
                    match val {
                        Value::String(val) => vec.push(val.as_ref()),
                        _ => unreachable!(),
                    }
                }
                Some(vec)
            }
            None => None,
            _ => unreachable!(),
        }
    }

    /// Set a value for a x509 certificate SHA-1 thumbprint parameter (x5t).
    ///
    /// # Arguments
    /// * `value` - A x509 certificate SHA-1 thumbprint
    pub fn set_x509_certificate_sha1_thumbprint(&mut self, value: Option<String>) {
        match value {
            Some(val) => {
                self.params.insert("x5t".to_string(), json!(val));
            }
            None => {
                self.params.remove("x5t");
            }
        }
    }

    /// Return a value for a x509 certificate SHA-1 thumbprint parameter (x5t).
    pub fn x509_certificate_sha1_thumbprint(&self) -> Option<&str> {
        match self.params.get("x5t") {
            Some(Value::String(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    /// Set a value for a x509 certificate SHA-256 thumbprint parameter (x5t#S256).
    ///
    /// # Arguments
    /// * `value` - A x509 certificate SHA-256 thumbprint
    pub fn set_x509_certificate_sha256_thumbprint(&mut self, value: Option<String>) {
        match value {
            Some(val) => {
                self.params.insert("x5t#S256".to_string(), json!(val));
            }
            None => {
                self.params.remove("x5t#S256");
            }
        }
    }

    /// Return a value for a x509 certificate SHA-256 thumbprint parameter (x5t#S256).
    pub fn x509_certificate_sha256_thumbprint(&self) -> Option<&str> {
        match self.params.get("x5t#S256") {
            Some(Value::String(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    /// Set a value for a parameter of a specified key.
    ///
    /// # Arguments
    /// * `key` - A key name of a parameter
    /// * `value` - A typed value of a parameter
    pub fn set_parameter(&mut self, key: &str, value: Option<Value>) -> &mut Self {
        match key {
            "kty" => match &value {
                Some(Value::String(_)) => {}
                _ => panic!("A parameter {} must be string type.", key),
            },
            "use" | "alg" | "kid" | "x5u" | "x5t" | "x5t#S256" => match &value {
                Some(Value::String(_)) => {}
                None => {}
                _ => panic!("A parameter {} must be string type.", key),
            },
            "key_ops" | "x5c" => match &value {
                Some(Value::Array(vals)) => {
                    for val in vals {
                        match val {
                            Value::String(_) => {}
                            _ => panic!("A item of the parameter {} must be string type.", key),
                        }
                    }
                }
                None => {}
                _ => panic!("A parameter {} must be array type.", key),
            },
            _ => {}
        }
        match value {
            Some(val) => {
                self.params.insert(key.to_string(), val);
            }
            None => {
                self.params.remove(key);
            }
        }
        self
    }

    /// Return a value for a parameter of a specified key.
    ///
    /// # Arguments
    /// * `key` - A key name of a parameter
    pub fn parameter(&self, key: &str) -> Option<&Value> {
        self.params.get(key)
    }

    /// Return parameters
    pub fn parameters(&self) -> &Map<String, Value> {
        &self.params
    }
}

impl AsRef<Map<String, Value>> for Jwk {
    fn as_ref(&self) -> &Map<String, Value> {
        &self.params
    }
}

impl ToString for Jwk {
    fn to_string(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

/// Represents JWK set.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JwkSet {
    keys: Vec<Jwk>,
}

impl JwkSet {
    pub fn new() -> Self {
        Self { keys: Vec::new() }
    }

    pub fn from_reader(input: &mut dyn Read) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let jwk_set: Self = serde_json::from_reader(input)?;
            Ok(jwk_set)
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn from_slice(input: impl AsRef<[u8]>) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let jwk_set: Self = serde_json::from_slice(input.as_ref())?;
            Ok(jwk_set)
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }
}

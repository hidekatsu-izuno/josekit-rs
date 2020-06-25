use std::io::Read;
use serde::{Serialize, Deserialize};
use serde_json::{Map, Value};

use crate::error::JoseError;

/// Represents JWK object.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Jwk {
    #[serde(rename = "kty")]
    pub key_type: String,

    #[serde(rename = "use")]
    pub key_use: Option<String>,

    #[serde(rename = "key_ops")]
    pub key_operations: Option<Vec<String>>,

    #[serde(rename = "alg")]
    pub algorithm: Option<String>,

    #[serde(rename = "kid")]
    pub key_id: Option<String>,

    #[serde(rename = "x5u")]
    pub x509_url: Option<String>,

    #[serde(rename = "x5c")]
    pub x509_certificate_chain: Option<Vec<String>>,

    #[serde(rename = "x5t")]
    pub x509_certificate_sha1_thumbprint: Option<String>,

    #[serde(rename = "x5t#S256")]
    pub x509_certificate_sha256_thumbprint: Option<String>,

    #[serde(flatten)]
    params: Map<String, Value>,
}

impl Jwk {
    pub fn new(key_type: &str) -> Self {
        Self {
            key_type: key_type.to_string(),
            key_use: None,
            key_operations: None,
            algorithm: None,
            key_id: None,
            x509_url: None,
            x509_certificate_chain: None,
            x509_certificate_sha1_thumbprint: None,
            x509_certificate_sha256_thumbprint: None,
            params: Map::new(),
        }
    }

    pub fn from_reader(input: &mut dyn Read) -> Result<Jwk, JoseError> {
        (|| -> anyhow::Result<Jwk> {
            let jwk: Jwk = serde_json::from_reader(input)?;
            Ok(jwk)
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn from_slice(input: impl AsRef<[u8]>) -> Result<Jwk, JoseError> {
        (|| -> anyhow::Result<Jwk> {
            let jwk: Jwk = serde_json::from_slice(input.as_ref())?;
            Ok(jwk)
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }
    
    /// Set a value for a parameter of a specified key.
    ///
    /// # Arguments
    /// * `key` - A key name of a parameter
    /// * `value` - A typed value of a parameter
    pub fn set_parameter(&mut self, key: &str, value: &Value) -> &mut Self {
        match key {
            "kty" => match value {
                Value::String(val) => {
                    self.key_type = val.clone();
                },
                _ => panic!("A parameter kty must be string type."),
            },
            "use" => match value {
                Value::String(val) => {
                    self.key_use = Some(val.clone());
                },
                _ => panic!("A parameter use must be string type.")
            },
            "key_ops" => match value {
                Value::Array(vals) => {
                    let mut vec = Vec::new();
                    for val in vals {
                        match val {
                            Value::String(val) => {
                                vec.push(val.clone());
                            },
                            _ => panic!("A item of the parameter key_ops must be string type."),
                        }
                    }
                    self.key_operations = Some(vec);
                },
                _ => panic!("A parameter key_ops must be array type."),
            },
            "alg" => match value {
                Value::String(val) => {
                    self.algorithm = Some(val.clone());
                },
                _ => panic!("A parameter alg must be string type.")
            },
            "kid" => match value {
                Value::String(val) => {
                    self.key_id = Some(val.clone());
                },
                _ => panic!("A parameter kid must be string type."),
            },
            "x5u" => match value {
                Value::String(val) => {
                    self.x509_url = Some(val.clone());
                },
                _ => panic!("A parameter kid must be string type."),
            },
            "x5c" => match value {
                Value::Array(vals) => {
                    let mut vec = Vec::new();
                    for val in vals {
                        match val {
                            Value::String(val) => {
                                vec.push(val.clone());
                            },
                            _ => panic!("A item of the parameter key_ops must be string type."),
                        }
                    }
                    self.x509_certificate_chain = Some(vec);
                },
                _ => panic!("A parameter x5c must be array type."),
            },
            "x5t" => match value {
                Value::String(val) => {
                    self.x509_certificate_sha1_thumbprint = Some(val.clone());
                },
                _ => panic!("A parameter x5t must be string type."),
            },
            "x5t#S256" => match value {
                Value::String(val) => {
                    self.x509_certificate_sha256_thumbprint = Some(val.clone());
                },
                _ => panic!("A parameter x5t#S256 must be string type.")
            },
            _ => {
                self.params.insert(key.to_string(), (*value).clone());
            }
        }
        self
    }

    /// Unset a value for a parameter of a specified key.
    ///
    /// # Arguments
    /// * `key` - A key name of a parameter
    pub fn unset_parameter(&mut self, key: &str) -> &mut Self {
        match key {
            "kty" => {
                panic!("A parameter kty cannot unset.");
            },
            "use" => {
                self.key_use = None;
            },
            "key_ops" => {
                self.key_operations = None;
            },
            "alg" => {
                self.algorithm = None;
            },
            "kid" => {
                self.key_id = None;
            },
            "x5u" => {
                self.x509_url = None;
            },
            "x5c" => {
                self.x509_certificate_chain = None;
            },
            "x5t" => {
                self.x509_certificate_sha1_thumbprint = None;
            },
            "x5t#S256" => {
                self.x509_certificate_sha256_thumbprint = None;
            },
            _ => {
                self.params.remove(key);
            }
        }
        self
    }
    
    /// Return a value for a parameter of a specified key.
    ///
    /// # Arguments
    /// * `key` - A key name of a parameter
    pub fn parameter(&self, key: &str) -> Option<Value> {
        match key {
            "kty" => Some(Value::String(self.key_type.clone())),
            "use" => match &self.key_use {
                Some(val) => Some(Value::String(val.clone())),
                None => None,
            },
            "key_ops" => match &self.key_operations {
                Some(vals) => {
                    let mut vec = Vec::with_capacity(vals.len());
                    for val in vals {
                        vec.push(Value::String(val.clone()));
                    }
                    Some(Value::Array(vec))
                },
                None => None,
            },
            "alg" => match &self.algorithm {
                Some(val) => Some(Value::String(val.clone())),
                None => None,
            },
            "kid" => match &self.key_id {
                Some(val) => Some(Value::String(val.clone())),
                None => None,
            },
            "x5u" => match &self.x509_url {
                Some(val) => Some(Value::String(val.clone())),
                None => None,
            },
            "x5c" => match &self.x509_certificate_chain {
                Some(vals) => {
                    let mut vec = Vec::with_capacity(vals.len());
                    for val in vals {
                        vec.push(Value::String(val.clone()));
                    }
                    Some(Value::Array(vec))
                },
                None => None,
            },
            "x5t" => match &self.x509_certificate_sha1_thumbprint {
                Some(val) => Some(Value::String(val.clone())),
                None => None,
            },
            "x5t#S256" => match &self.x509_certificate_sha256_thumbprint {
                Some(val) => Some(Value::String(val.clone())),
                None => None,
            },
            _ => match self.params.get(key) {
                Some(val) => Some(val.clone()),
                None => None,
            }
        }
    }
}

/// Represents JWK set.
#[derive(Debug, Eq, PartialEq)]
pub struct JwkSet {
    keys: Vec<Jwk>
}

impl JwkSet {

}

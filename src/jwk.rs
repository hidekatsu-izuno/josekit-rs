use std::io::Read;
use std::sync::Arc;
use std::collections::BTreeMap;
use std::ops::Bound::Included;
use std::string::ToString;
use anyhow::bail;
use serde::{Serialize, Serializer};
use serde::ser::{SerializeMap};
use serde_json::{json, Map, Value};

use crate::error::JoseError;

/// Represents JWK object.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Jwk {
    key_operations: Option<Vec<String>>,
    x509_certificate_chain: Option<Vec<Vec<u8>>>,
    x509_certificate_sha1_thumbprint: Option<Vec<u8>>,
    x509_certificate_sha256_thumbprint: Option<Vec<u8>>,
    params: Map<String, Value>,
}

impl Jwk {
    pub fn new(key_type: &str) -> Self {
        let mut params = Map::new();
        params.insert("kty".to_string(), json!(key_type));
        Self {
            key_operations: None,
            x509_certificate_chain: None,
            x509_certificate_sha1_thumbprint: None,
            x509_certificate_sha256_thumbprint: None,
            params,
        }
    }

    pub fn from_map(map: Map<String, Value>) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let mut key_operations = None;
            let mut x509_certificate_chain = None;
            let mut x509_certificate_sha1_thumbprint = None;
            let mut x509_certificate_sha256_thumbprint = None;
            for (key, value) in &map {
                match key.as_str() {
                    "jku" | "x5u" | "kid" | "typ" | "cty" => match value {
                        Value::String(_) => {},
                        _ => bail!("The JWK {} parameter must be a string.", key),
                    },
                    "key_ops" => key_operations = match value {
                        Value::Array(vals) => {
                            let mut vec = Vec::with_capacity(vals.len());
                            for val in vals {
                                match val {
                                    Value::String(val) => vec.push(val.to_string()),
                                    _ => bail!("An element of the JWK {} parameter must be a string.", key),
                                }
                            }
                            Some(vec)
                        },
                        _ => bail!("The JWT {} parameter must be a array.", key),
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
                                    _ => bail!("An element of the JWK {} parameter must be a string.", key),
                                }
                            }
                            Some(vec)
                        },
                        _ => bail!("The JWK {} parameter must be a array.", key),
                    },
                    "x5t" => x509_certificate_sha1_thumbprint = match value {
                        Value::String(val) => Some(base64::decode_config(val, base64::URL_SAFE_NO_PAD)?),
                        _ => bail!("The JWK {} parameter must be a string.", key),
                    },
                    "x5t#S256" => x509_certificate_sha256_thumbprint = match value {
                        Value::String(val) => Some(base64::decode_config(val, base64::URL_SAFE_NO_PAD)?),
                        _ => bail!("The JWK {} parameter must be a string.", key),
                    },
                    _ => {}
                }
            }

            Ok(Self {
                key_operations,
                x509_certificate_chain,
                x509_certificate_sha1_thumbprint,
                x509_certificate_sha256_thumbprint,
                params: map,
            })
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err)
        })
    }

    pub fn from_reader(input: &mut dyn Read) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let params: Map<String, Value> = serde_json::from_reader(input)?;
            Ok(Self::from_map(params)?)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err)
        })
    }

    pub fn from_slice(input: impl AsRef<[u8]>) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let params: Map<String, Value> = serde_json::from_slice(input.as_ref())?;
            Ok(Self::from_map(params)?)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err)
        })
    }

    /// Set a value for a key type parameter (kty).
    ///
    /// # Arguments
    /// * `value` - A key type
    pub fn set_key_type(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.params.insert("kty".to_string(), Value::String(value));
    }

    /// Return a value for a key type parameter (kty).
    pub fn key_type(&self) -> &str {
        match self.params.get("kty") {
            Some(Value::String(val)) => val,
            _ => unreachable!("The JWS kty parameter is required."),
        }
    }

    /// Set a value for a key use parameter (use).
    ///
    /// # Arguments
    /// * `value` - A key use
    pub fn set_key_use(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.params.insert("use".to_string(), Value::String(value));
    }

    /// Return a value for a key use parameter (use).
    pub fn key_use(&self) -> Option<&str> {
        match self.params.get("use") {
            Some(Value::String(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    /// Set values for a key operations parameter (key_ops).
    ///
    /// # Arguments
    /// * `values` - key operations
    pub fn set_key_operations(&mut self, values: Vec<impl Into<String>>) {
        let mut vec1 = Vec::with_capacity(values.len());
        let mut vec2 = Vec::with_capacity(values.len());
        for val in values {
            let val: String = val.into();
            vec1.push(Value::String(val.clone()));
            vec2.push(val);
        }
        self.params.insert("key_ops".to_string(), Value::Array(vec1));
        self.key_operations = Some(vec2);
    }

    /// Return values for a key operations parameter (key_ops).
    pub fn key_operations(&self) -> Option<&Vec<String>> {
        match self.key_operations {
            Some(ref val) => Some(val),
            None => None,
        }
    }

    /// Set a value for a algorithm parameter (alg).
    ///
    /// # Arguments
    /// * `value` - A algorithm
    pub fn set_algorithm(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.params.insert("alg".to_string(), Value::String(value));
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
    pub fn set_key_id(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.params.insert("kid".to_string(), Value::String(value));
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
    pub fn set_x509_url(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.params.insert("x5u".to_string(), Value::String(value));
    }

    /// Return a value for a x509 url parameter (x5u).
    pub fn x509_url(&self) -> Option<&str> {
        match self.params.get("x5u") {
            Some(Value::String(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    /// Set a value for a x509 certificate SHA-1 thumbprint parameter (x5t).
    ///
    /// # Arguments
    /// * `value` - A x509 certificate SHA-1 thumbprint
    pub fn set_x509_certificate_sha1_thumbprint(&mut self, value: Vec<u8>) {
        self.params.insert("x5t".to_string(), Value::String(base64::encode_config(&value, base64::URL_SAFE_NO_PAD)));
        self.x509_certificate_sha1_thumbprint = Some(value);
    }

    /// Return a value for a x509 certificate SHA-1 thumbprint parameter (x5t).
    pub fn x509_certificate_sha1_thumbprint(&self) -> Option<&Vec<u8>> {
        match self.x509_certificate_sha1_thumbprint {
            Some(ref val) => Some(val),
            None => None,
        }
    }

    /// Set a value for a x509 certificate SHA-256 thumbprint parameter (x5t#S256).
    ///
    /// # Arguments
    /// * `value` - A x509 certificate SHA-256 thumbprint
    pub fn set_x509_certificate_sha256_thumbprint(&mut self, value: Vec<u8>) {
        self.params.insert("x5t#S256".to_string(), Value::String(base64::encode_config(&value, base64::URL_SAFE_NO_PAD)));
        self.x509_certificate_sha256_thumbprint = Some(value);
    }

    /// Return a value for a x509 certificate SHA-256 thumbprint parameter (x5t#S256).
    pub fn x509_certificate_sha256_thumbprint(&self) -> Option<&Vec<u8>> {
        match self.x509_certificate_sha256_thumbprint {
            Some(ref val) => Some(val),
            None => None,
        }
    }

    /// Set values for a X.509 certificate chain parameter (x5c).
    ///
    /// # Arguments
    /// * `values` - X.509 certificate chain
    pub fn set_x509_certificate_chain(&mut self, values: Vec<Vec<u8>>) {
        let mut vec = Vec::with_capacity(values.len());
        for val in &values {
            vec.push(Value::String(base64::encode_config(&val, base64::URL_SAFE_NO_PAD)));
        }
        self.params.insert("x5c".to_string(), Value::Array(vec));
        self.x509_certificate_chain = Some(values);
    }

    /// Return values for a X.509 certificate chain parameter (x5c).
    pub fn x509_certificate_chain(&self) -> Option<&Vec<Vec<u8>>> {
        match self.x509_certificate_chain {
            Some(ref val) => Some(val),
            None => None,
        }
    }

    /// Set a value for a parameter of a specified key.
    ///
    /// # Arguments
    /// * `key` - A key name of a parameter
    /// * `value` - A typed value of a parameter
    pub fn set_parameter(&mut self, key: &str, value: Option<Value>) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            match key {
                "kty" => match &value {
                    Some(Value::String(_)) => {}
                    _ => bail!("The JWK {} parameter must be a string.", key),
                },
                "use" | "alg" | "kid" | "x5u" => match &value {
                    Some(Value::String(_)) => {
                        self.params.insert(key.to_string(), value.unwrap());
                    },
                    None => {
                        self.params.remove(key);
                    },
                    _ => bail!("The JWK {} parameter must be a string.", key),
                },
                "key_ops" => match &value {
                    Some(Value::Array(vals)) => {
                        let mut vec = Vec::with_capacity(vals.len());
                        for val in vals {
                            match val {
                                Value::String(val) => vec.push(val.to_string()),
                                _ => bail!("An element of the JWT {} parameter must be a string.", key),
                            }
                        }
                        self.key_operations = Some(vec);
                        self.params.insert(key.to_string(), value.unwrap());
                    },
                    None => {
                        self.key_operations = None;
                        self.params.remove(key);
                    },
                    _ => bail!("The JWT {} parameter must be a array.", key),
                },
                "x5t" => match &value {
                    Some(Value::String(val)) => {
                        self.x509_certificate_sha1_thumbprint = Some(base64::decode_config(val, base64::URL_SAFE_NO_PAD)?);
                        self.params.insert(key.to_string(), value.unwrap());
                    },
                    None => {
                        self.x509_certificate_sha1_thumbprint = None;
                        self.params.remove(key);
                    },
                    _ => bail!("The JWK {} parameter must be a string.", key),
                },
                "x5t#S256" => match &value {
                    Some(Value::String(val)) => {
                        self.x509_certificate_sha256_thumbprint = Some(base64::decode_config(val, base64::URL_SAFE_NO_PAD)?);
                        self.params.insert(key.to_string(), value.unwrap());
                    },
                    None => {
                        self.x509_certificate_sha256_thumbprint = None;
                        self.params.remove(key);
                    },
                    _ => bail!("The JWK {} parameter must be a string.", key),
                },
                "x5c" => match &value {
                    Some(Value::Array(vals)) => {
                        let mut vec = Vec::with_capacity(vals.len());
                        for val in vals {
                            match val {
                                Value::String(val) => {
                                    let decoded = base64::decode_config(val, base64::URL_SAFE_NO_PAD)?;
                                    vec.push(decoded);
                                },
                                _ => bail!("An element of the JWK {} parameter must be a string.", key),
                            }
                        }
                        self.x509_certificate_chain = Some(vec);
                        self.params.insert(key.to_string(), value.unwrap());
                    },
                    None => {
                        self.x509_certificate_chain = None;
                        self.params.remove(key);
                    },
                    _ => bail!("The JWK {} parameter must be a string.", key),
                },
                _ => match &value {
                    Some(_) => {
                        self.params.insert(key.to_string(), value.unwrap());
                    }
                    None => {
                        self.params.remove(key);
                    }
                }
            }
            
            Ok(())
        })()
        .map_err(|err| JoseError::InvalidJwtFormat(err))
    }

    /// Return a value for a parameter of a specified key.
    ///
    /// # Arguments
    /// * `key` - A key name of a parameter
    pub fn parameter(&self, key: &str) -> Option<&Value> {
        self.params.get(key)
    }
}

impl AsRef<Map<String, Value>> for Jwk {
    fn as_ref(&self) -> &Map<String, Value> {
        &self.params
    }
}

impl Serialize for Jwk {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.params.len()))?;
        for (k, v) in &self.params {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

impl ToString for Jwk {
    fn to_string(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }
}

/// Represents JWK set.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct JwkSet {
    keys: Vec<Arc<Jwk>>,
    params: Map<String, Value>,

    kid_map: BTreeMap<(String, usize), Arc<Jwk>>,
}

impl JwkSet {
    pub fn new() -> Self {
        Self {
            keys: Vec::new(),
            params: Map::new(),
            kid_map: BTreeMap::new(),
        }
    }

    pub fn from_map(map: Map<String, Value>) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let mut kid_map = BTreeMap::new();
            let keys = match map.get("keys") {
                Some(Value::Array(vals)) => {
                    let mut vec = Vec::new();
                    for (i, val) in vals.iter().enumerate() {
                        match val {
                            Value::Object(val) => {
                                let jwk = Arc::new(Jwk::from_map(val.clone())?);
                                if let Some(kid) = jwk.key_id() {
                                    kid_map.insert((kid.to_string(), i), Arc::clone(&jwk));
                                }
                                vec.push(jwk);
                            },
                            _ => bail!("An element of the JWK set keys parameter must be a object."),
                        }
                    }
                    vec
                },
                Some(_) => bail!("The JWT keys parameter must be a array."),
                None => bail!("The JWK set must have a keys parameter."),
            };

            Ok(Self {
                keys,
                params: map,
                kid_map: kid_map,
            })
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err)
        })
    }

    pub fn from_reader(input: &mut dyn Read) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let keys: Map<String, Value> = serde_json::from_reader(input)?;
            Ok(Self::from_map(keys)?)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err)
        })
    }

    pub fn from_slice(input: impl AsRef<[u8]>) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let keys: Map<String, Value> = serde_json::from_slice(input.as_ref())?;
            Ok(Self::from_map(keys)?)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err)
        })
    }

    pub fn get(&self, key_id: &str) -> Vec<&Jwk> {
        let mut vec = Vec::new();
        for (_, val) in self.kid_map.range((
                Included((key_id.to_string(), 0)), 
                Included((key_id.to_string(), usize::MAX))
            )) {
            let jwk: &Jwk = &val;
            vec.push(jwk);
        }
        vec
    }

    pub fn keys(&self) -> Vec<&Jwk> {
        self.keys.iter().map(|e| e.as_ref()).collect()
    }

    pub fn push_key(&mut self, jwk: Jwk) {
        match self.params.get_mut("keys") {
            Some(Value::Array(keys)) => {
                keys.push(Value::Object(jwk.as_ref().clone()));
            },
            _ => unreachable!(),
        }

        let jwk = Arc::new(jwk);
        if let Some(kid) = jwk.key_id() {
            self.kid_map.insert((kid.to_string(), self.keys.len()), Arc::clone(&jwk));
        }
        self.keys.push(jwk);
    }

    pub fn remove_key(&mut self, jwk: &Jwk) {
        let index = self.keys.iter().position(|e| e.as_ref() == jwk);
        if let Some(index) = index {
            match self.params.get_mut("keys") {
                Some(Value::Array(keys)) => {
                    keys.remove(index);
                },
                _ => unreachable!(),
            }
            self.keys.remove(index);
        }
    }
}

impl AsRef<Map<String, Value>> for JwkSet {
    fn as_ref(&self) -> &Map<String, Value> {
        &self.params
    }
}

impl Serialize for JwkSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.params.len()))?;
        for (k, v) in &self.params {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

impl ToString for JwkSet {
    fn to_string(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }
}


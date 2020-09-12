use std::fmt::Display;
use std::io::Read;
use std::string::ToString;

use anyhow::bail;
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};
use serde_json::{Map, Value};

use crate::util;
use crate::JoseError;

/// Represents JWK object.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Jwk {
    map: Map<String, Value>,
}

impl Jwk {
    pub fn new(key_type: &str) -> Self {
        Self {
            map: {
                let mut map = Map::new();
                map.insert("kty".to_string(), Value::String(key_type.to_string()));
                map
            },
        }
    }

    pub fn from_map(map: impl Into<Map<String, Value>>) -> Result<Self, JoseError> {
        let map: Map<String, Value> = map.into();
        Self::check_map(&map)?;

        Ok(Self { map })
    }

    pub fn from_reader(input: &mut dyn Read) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let map: Map<String, Value> = serde_json::from_reader(input)?;
            Ok(Self::from_map(map)?)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err),
        })
    }

    pub fn from_bytes(input: impl AsRef<[u8]>) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let map: Map<String, Value> = serde_json::from_slice(input.as_ref())?;
            Ok(Self::from_map(map)?)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwtFormat(err),
        })
    }

    /// Set a value for a key type parameter (kty).
    ///
    /// # Arguments
    /// * `value` - A key type
    pub fn set_key_type(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.map.insert("kty".to_string(), Value::String(value));
    }

    /// Return a value for a key type parameter (kty).
    pub fn key_type(&self) -> &str {
        match self.map.get("kty") {
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
        self.map.insert("use".to_string(), Value::String(value));
    }

    /// Return a value for a key use parameter (use).
    pub fn key_use(&self) -> Option<&str> {
        match self.map.get("use") {
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
        let mut vec = Vec::with_capacity(values.len());
        for val in values {
            let val: String = val.into();
            vec.push(Value::String(val.clone()));
        }
        self.map.insert("key_ops".to_string(), Value::Array(vec));
    }

    /// Return values for a key operations parameter (key_ops).
    pub fn key_operations(&self) -> Option<Vec<&str>> {
        match self.map.get("key_ops") {
            Some(Value::Array(vals)) => {
                let mut vec = Vec::with_capacity(vals.len());
                for val in vals {
                    match val {
                        Value::String(val2) => vec.push(val2.as_str()),
                        _ => return None,
                    }
                }
                Some(vec)
            }
            _ => None,
        }
    }

    pub fn is_for_key_operation(&self, key_operation: &str) -> bool {
        match self.map.get("key_ops") {
            Some(Value::Array(vals)) => vals.iter().any(|val| match val {
                Value::String(val2) if val2 == key_operation => true,
                _ => false,
            }),
            Some(_) => false,
            None => true,
        }
    }

    /// Set a value for a algorithm parameter (alg).
    ///
    /// # Arguments
    /// * `value` - A algorithm
    pub fn set_algorithm(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.map.insert("alg".to_string(), Value::String(value));
    }

    /// Return a value for a algorithm parameter (alg).
    pub fn algorithm(&self) -> Option<&str> {
        match self.map.get("alg") {
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
        self.map.insert("kid".to_string(), Value::String(value));
    }

    /// Return a value for a key ID parameter (kid).
    pub fn key_id(&self) -> Option<&str> {
        match self.map.get("kid") {
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
        self.map.insert("x5u".to_string(), Value::String(value));
    }

    /// Return a value for a x509 url parameter (x5u).
    pub fn x509_url(&self) -> Option<&str> {
        match self.map.get("x5u") {
            Some(Value::String(val)) => Some(val),
            None => None,
            _ => unreachable!(),
        }
    }

    /// Set a value for a x509 certificate SHA-1 thumbprint parameter (x5t).
    ///
    /// # Arguments
    /// * `value` - A x509 certificate SHA-1 thumbprint
    pub fn set_x509_certificate_sha1_thumbprint(&mut self, value: impl AsRef<[u8]>) {
        self.map.insert(
            "x5t".to_string(),
            Value::String(base64::encode_config(&value, base64::URL_SAFE_NO_PAD)),
        );
    }

    /// Return a value for a x509 certificate SHA-1 thumbprint parameter (x5t).
    pub fn x509_certificate_sha1_thumbprint(&self) -> Option<Vec<u8>> {
        match self.map.get("x5t") {
            Some(Value::String(val)) => match base64::decode_config(val, base64::URL_SAFE_NO_PAD) {
                Ok(val) => Some(val),
                Err(_) => None,
            },
            _ => None,
        }
    }

    /// Set a value for a x509 certificate SHA-256 thumbprint parameter (x5t#S256).
    ///
    /// # Arguments
    /// * `value` - A x509 certificate SHA-256 thumbprint
    pub fn set_x509_certificate_sha256_thumbprint(&mut self, value: impl AsRef<[u8]>) {
        self.map.insert(
            "x5t#S256".to_string(),
            Value::String(base64::encode_config(&value, base64::URL_SAFE_NO_PAD)),
        );
    }

    /// Return a value for a x509 certificate SHA-256 thumbprint parameter (x5t#S256).
    pub fn x509_certificate_sha256_thumbprint(&self) -> Option<Vec<u8>> {
        match self.map.get("x5t#S256") {
            Some(Value::String(val)) => match base64::decode_config(val, base64::URL_SAFE_NO_PAD) {
                Ok(val) => Some(val),
                Err(_) => None,
            },
            _ => None,
        }
    }

    /// Set values for a X.509 certificate chain parameter (x5c).
    ///
    /// # Arguments
    /// * `values` - X.509 certificate chain
    pub fn set_x509_certificate_chain(&mut self, values: &Vec<impl AsRef<[u8]>>) {
        let mut vec = Vec::with_capacity(values.len());
        for val in values {
            vec.push(Value::String(base64::encode_config(
                &val,
                base64::URL_SAFE_NO_PAD,
            )));
        }
        self.map.insert("x5c".to_string(), Value::Array(vec));
    }

    /// Return values for a X.509 certificate chain parameter (x5c).
    pub fn x509_certificate_chain(&self) -> Option<Vec<Vec<u8>>> {
        match self.map.get("x5c") {
            Some(Value::Array(vals)) => {
                let mut vec = Vec::with_capacity(vals.len());
                for val in vals {
                    match val {
                        Value::String(val2) => {
                            match base64::decode_config(val2, base64::URL_SAFE_NO_PAD) {
                                Ok(val3) => vec.push(val3),
                                Err(_) => return None,
                            }
                        }
                        _ => return None,
                    }
                }
                Some(vec)
            }
            _ => None,
        }
    }

    /// Set a value for a curve parameter (crv).
    ///
    /// # Arguments
    /// * `value` - A curve
    pub fn set_curve(&mut self, value: impl Into<String>) {
        let value: String = value.into();
        self.map.insert("crv".to_string(), Value::String(value));
    }

    /// Return a value for a curve parameter (crv).
    pub fn curve(&self) -> Option<&str> {
        match self.map.get("crv") {
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
    pub fn set_parameter(&mut self, key: &str, value: Option<Value>) -> Result<(), JoseError> {
        match value {
            Some(val) => {
                Self::check_parameter(key, &val)?;
                self.map.insert(key.to_string(), val);
            }
            None => {
                (|| -> anyhow::Result<()> {
                    match key {
                        "kty" => bail!("The JWK {} parameter must be required.", key),
                        _ => {}
                    }
                    Ok(())
                })()
                .map_err(|err| JoseError::InvalidJwkFormat(err))?;

                self.map.remove(key);
            }
        }

        Ok(())
    }

    /// Return a value for a parameter of a specified key.
    ///
    /// # Arguments
    /// * `key` - A key name of a parameter
    pub fn parameter(&self, key: &str) -> Option<&Value> {
        self.map.get(key)
    }

    pub(crate) fn check_map(map: &Map<String, Value>) -> Result<(), JoseError> {
        for (key, value) in map {
            Self::check_parameter(key, value)?;
        }

        (|| -> anyhow::Result<()> {
            if !map.contains_key("kty") {
                bail!("The JWK kty parameter is required.");
            }
            Ok(())
        })()
        .map_err(|err| JoseError::InvalidJwsFormat(err))
    }

    fn check_parameter(key: &str, value: &Value) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            match key {
                "kty" | "use" | "alg" | "kid" | "x5u" | "crv" => match &value {
                    Value::String(_) => {}
                    _ => bail!("The JWK {} parameter must be a string.", key),
                },
                "key_ops" => match &value {
                    Value::Array(vals) => {
                        for val in vals {
                            match val {
                                Value::String(_) => {}
                                _ => bail!(
                                    "An element of the JWK {} parameter must be a string.",
                                    key
                                ),
                            }
                        }
                    }
                    _ => bail!("The JWK {} parameter must be a array of string.", key),
                },
                "x5t" | "x5t#S256" | "k" | "d" | "p" | "q" | "dp" | "dq" | "qi" | "x" | "y" => {
                    match &value {
                        Value::String(val) => {
                            if !util::is_base64_url_safe_nopad(val) {
                                bail!("The JWK {} parameter must be a base64 string.", key);
                            }
                        }
                        _ => bail!("The JWK {} parameter must be a string.", key),
                    }
                }
                "x5c" => match &value {
                    Value::Array(vals) => {
                        for val in vals {
                            match val {
                                Value::String(val) => {
                                    if !util::is_base64_url_safe_nopad(val) {
                                        bail!("The JWK {} parameter must be a base64 string.", key);
                                    }
                                }
                                _ => bail!(
                                    "An element of the JWK {} parameter must be a string.",
                                    key
                                ),
                            }
                        }
                    }
                    _ => bail!("The JWK {} parameter must be a array of string.", key),
                },
                _ => {}
            }

            Ok(())
        })()
        .map_err(|err| JoseError::InvalidJwkFormat(err))
    }
}

impl AsRef<Map<String, Value>> for Jwk {
    fn as_ref(&self) -> &Map<String, Value> {
        &self.map
    }
}

impl Into<Map<String, Value>> for Jwk {
    fn into(self) -> Map<String, Value> {
        self.map
    }
}

impl Serialize for Jwk {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.map.len()))?;
        for (k, v) in &self.map {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

impl Display for Jwk {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let val = serde_json::to_string(&self).map_err(|_e| std::fmt::Error {})?;
        fmt.write_str(&val)
    }
}

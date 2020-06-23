use std::io::Read;
use serde_json::{Map, Value};

use crate::error::JoseError;

/// Represents JWK object.
#[derive(Debug, Eq, PartialEq)]
pub struct Jwk {
    params: Map<String, Value>,
}

impl Jwk {
    pub fn from_reader(input: &mut dyn Read) -> Result<Jwk, JoseError> {
        (|| -> anyhow::Result<Jwk> {
            let params: Map<String, Value> = serde_json::from_reader(input)?;

            Ok(Jwk {
                params
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn from_slice(input: impl AsRef<[u8]>) -> Result<Jwk, JoseError> {
        (|| -> anyhow::Result<Jwk> {
            let params: Map<String, Value> = serde_json::from_slice(input.as_ref())?;

            Ok(Jwk {
                params
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }
}

/// Represents JWK set.
#[derive(Debug, Eq, PartialEq)]
pub struct JwkSet {
    keys: Vec<Jwk>
}

impl JwkSet {

}

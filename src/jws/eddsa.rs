use anyhow::{anyhow, bail};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{HasPublic, PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use openssl::bn::BigNum;
use serde_json::{Map, Value};

use crate::jws::{JwsAlgorithm, JwsSigner, JwsVerifier};
use crate::jws::util::{json_eq, json_base64_bytes};
use crate::error::JoseError;

/// EdDSA
pub const EDDSA: EddsaJwsAlgorithm = EddsaJwsAlgorithm::new("EdDSA");

#[derive(Debug, Eq, PartialEq)]
pub struct EddsaJwsAlgorithm {
    name: &'static str
}

impl EddsaJwsAlgorithm {
    /// Return a new instance.
    ///
    /// # Arguments
    /// * `name` - A algrithm name.
    /// * `hash_algorithm` - A algrithm name.
    const fn new(name: &'static str) -> Self {
        EddsaJwsAlgorithm {
            name
        }
    }
}

impl JwsAlgorithm for EddsaJwsAlgorithm {
    fn name(&self) -> &str {
        self.name
    }
}

pub struct EddsaJwsSigner<'a> {
    algorithm: &'a EddsaJwsAlgorithm,
    private_key: PKey<Private>,
}

impl<'a> JwsSigner<EddsaJwsAlgorithm> for EddsaJwsSigner<'a> {
    fn algorithm(&self) -> &EddsaJwsAlgorithm {
        &self.algorithm
    }

    fn sign(&self, data: &[&[u8]]) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let mut signer = Signer::new_without_digest(&self.private_key)?;
            for part in data {
                signer.update(part)?;
            }
            let signature = signer.sign_to_vec()?;
            Ok(signature)
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }
}

pub struct EddsaJwsVerifier<'a> {
    algorithm: &'a EddsaJwsAlgorithm,
    public_key: PKey<Public>,
}

impl<'a> JwsVerifier<EddsaJwsAlgorithm> for EddsaJwsVerifier<'a> {
    fn algorithm(&self) -> &EddsaJwsAlgorithm {
        &self.algorithm
    }

    fn verify(&self, data: &[&[u8]], signature: &[u8]) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            let mut verifier = Verifier::new_without_digest(&self.public_key)?;
            for part in data {
                verifier.update(part)?;
            }
            verifier.verify(signature)?;
            Ok(())
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }
}
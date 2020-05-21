use anyhow::{anyhow, bail};
use openssl::hash::MessageDigest;
use openssl::memcmp;
use openssl::pkey::{PKey, Private};
use serde_json::{Map, Value};

use crate::algorithm::{Algorithm, HashAlgorithm, Signer, Verifier};
use crate::algorithm::openssl::{json_eq, json_base64_bytes};
use crate::error::JwtError;

#[derive(Debug, Eq, PartialEq)]
pub struct HmacAlgorithm {
    name: &'static str,
    hash_algorithm: HashAlgorithm,
}

impl HmacAlgorithm {
    /// Return a new instance.
    ///
    /// # Arguments
    /// * `hash_algorithm` - A algrithm name.
    pub const fn new(name: &'static str, hash_algorithm: HashAlgorithm) -> Self {
        HmacAlgorithm {
            name,
            hash_algorithm
        }
    }

    /// Return a signer from a private key of JWK format.
    ///
    /// # Arguments
    /// * `data` - A private key.
    pub fn signer_from_jwk<'a>(
        &'a self,
        jwk_str: &[u8],
    ) -> Result<impl Signer<HmacAlgorithm> + Verifier<HmacAlgorithm> + 'a, JwtError> {
        let key_data = (|| -> anyhow::Result<Vec<u8>> {
            let map: Map<String, Value> = serde_json::from_slice(jwk_str)
                .map_err(|err| anyhow!(err))?;

            json_eq(&map, "alg", &self.name())?;
            json_eq(&map, "kty", "oct")?;
            json_eq(&map, "use", "sig")?;

            let key_data = json_base64_bytes(&map, "k")
                .map_err(|err| anyhow!(err))?;
            Ok(key_data)
        })()
        .map_err(|err| JwtError::InvalidKeyFormat(err))?;

        self.signer_from_slice(&key_data)
    }

    /// Return a signer from a private key.
    ///
    /// # Arguments
    /// * `data` - A private key.
    pub fn signer_from_slice<'a>(
        &'a self,
        data: &[u8],
    ) -> Result<impl Signer<HmacAlgorithm> + Verifier<HmacAlgorithm> + 'a, JwtError> {
        PKey::hmac(&data)
            .map_err(|err| JwtError::InvalidKeyFormat(anyhow!(err)))
            .map(|val| HmacSigner {
                algorithm: &self,
                private_key: val,
            })
    }
}

impl Algorithm for HmacAlgorithm {
    fn name(&self) -> &str {
        self.name
    }
}

pub struct HmacSigner<'a> {
    algorithm: &'a HmacAlgorithm,
    private_key: PKey<Private>,
}

impl<'a> Signer<HmacAlgorithm> for HmacSigner<'a> {
    fn algorithm(&self) -> &HmacAlgorithm {
        &self.algorithm
    }

    fn sign(&self, data: &[&[u8]]) -> Result<Vec<u8>, JwtError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let message_digest = match self.algorithm.hash_algorithm {
                HashAlgorithm::SHA256 => MessageDigest::sha256(),
                HashAlgorithm::SHA384 => MessageDigest::sha384(),
                HashAlgorithm::SHA512 => MessageDigest::sha512(),
            };

            let mut signer = openssl::sign::Signer::new(message_digest, &self.private_key)?;
            for part in data {
                signer.update(part)?;
            }
            let signature = signer.sign_to_vec()?;
            Ok(signature)
        })()
        .map_err(|err| JwtError::InvalidSignature(err))
    }
}

impl<'a> Verifier<HmacAlgorithm> for HmacSigner<'a> {
    fn algorithm(&self) -> &HmacAlgorithm {
        &self.algorithm
    }

    fn verify(&self, data: &[&[u8]], signature: &[u8]) -> Result<(), JwtError> {
        (|| -> anyhow::Result<()> {
            let message_digest = match self.algorithm.hash_algorithm {
                HashAlgorithm::SHA256 => MessageDigest::sha256(),
                HashAlgorithm::SHA384 => MessageDigest::sha384(),
                HashAlgorithm::SHA512 => MessageDigest::sha512(),
            };

            let mut signer = openssl::sign::Signer::new(message_digest, &self.private_key)?;
            for part in data {
                signer.update(part)?;
            }
            let new_signature = signer.sign_to_vec()?;
            if !memcmp::eq(&new_signature, &signature) {
                bail!("Failed to verify.")
            }
            Ok(())
        })()
        .map_err(|err| JwtError::InvalidSignature(err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Result;

    #[test]
    fn sign_and_verify() -> Result<()> {
        let private_key = b"ABCDE12345";
        let data = b"abcde12345";

        for name in &[
            "HS256",
            "HS384",
            "HS512",
        ] {
            let alg = HmacAlgorithm::new(name, hash_algorithm(name));

            let signer = alg.signer_from_slice(private_key)?;
            let signature = signer.sign(&[data])?;
            signer.verify(&[data], &signature)?;
        }

        Ok(())
    }

    fn hash_algorithm(name: &str) -> HashAlgorithm {
        match name {
            "HS256" => HashAlgorithm::SHA256,
            "HS384" => HashAlgorithm::SHA384,
            "HS512" => HashAlgorithm::SHA512,
            _ => unreachable!()
        }
    }
}

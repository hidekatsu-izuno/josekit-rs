use anyhow::{anyhow, bail};
use openssl::hash::MessageDigest;
use openssl::memcmp;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use serde_json::{Map, Value};

use crate::jws::{JwsAlgorithm, HashAlgorithm, JwsSigner, JwsVerifier};
use crate::jws::util::{json_eq, json_base64_bytes};
use crate::error::JoseError;

/// HMAC using SHA-256
pub const HS256: HmacJwsAlgorithm = HmacJwsAlgorithm::new("HS256", HashAlgorithm::SHA256);

/// HMAC using SHA-384
pub const HS384: HmacJwsAlgorithm = HmacJwsAlgorithm::new("HS384", HashAlgorithm::SHA384);

/// HMAC using SHA-512
pub const HS512: HmacJwsAlgorithm = HmacJwsAlgorithm::new("HS512", HashAlgorithm::SHA512);

#[derive(Debug, Eq, PartialEq)]
pub struct HmacJwsAlgorithm {
    name: &'static str,
    hash_algorithm: HashAlgorithm,
}

impl HmacJwsAlgorithm {
    /// Return a new instance.
    ///
    /// # Arguments
    /// * `hash_algorithm` - A algrithm name.
    pub const fn new(name: &'static str, hash_algorithm: HashAlgorithm) -> Self {
        HmacJwsAlgorithm {
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
    ) -> Result<impl JwsSigner<Self> + JwsVerifier<Self> + 'a, JoseError> {
        let key_data = (|| -> anyhow::Result<Vec<u8>> {
            let map: Map<String, Value> = serde_json::from_slice(jwk_str)?;

            json_eq(&map, "alg", &self.name())?;
            json_eq(&map, "kty", "oct")?;
            json_eq(&map, "use", "sig")?;
            let key_data = json_base64_bytes(&map, "k")?;
            
            Ok(key_data)
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))?;

        self.signer_from_slice(&key_data)
    }

    /// Return a signer from a private key.
    ///
    /// # Arguments
    /// * `data` - A private key.
    pub fn signer_from_slice<'a>(
        &'a self,
        data: &[u8],
    ) -> Result<impl JwsSigner<Self> + JwsVerifier<Self> + 'a, JoseError> {
        PKey::hmac(&data)
            .map_err(|err| JoseError::InvalidKeyFormat(anyhow!(err)))
            .map(|val| HmacJwsSigner {
                algorithm: &self,
                private_key: val,
            })
    }
}

impl JwsAlgorithm for HmacJwsAlgorithm {
    fn name(&self) -> &str {
        self.name
    }
}

pub struct HmacJwsSigner<'a> {
    algorithm: &'a HmacJwsAlgorithm,
    private_key: PKey<Private>,
}

impl<'a> JwsSigner<HmacJwsAlgorithm> for HmacJwsSigner<'a> {
    fn algorithm(&self) -> &HmacJwsAlgorithm {
        &self.algorithm
    }

    fn sign(&self, data: &[&[u8]]) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let message_digest = match self.algorithm.hash_algorithm {
                HashAlgorithm::SHA256 => MessageDigest::sha256(),
                HashAlgorithm::SHA384 => MessageDigest::sha384(),
                HashAlgorithm::SHA512 => MessageDigest::sha512(),
            };

            let mut signer = Signer::new(message_digest, &self.private_key)?;
            for part in data {
                signer.update(part)?;
            }
            let signature = signer.sign_to_vec()?;
            Ok(signature)
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }
}

impl<'a> JwsVerifier<HmacJwsAlgorithm> for HmacJwsSigner<'a> {
    fn algorithm(&self) -> &HmacJwsAlgorithm {
        &self.algorithm
    }

    fn verify(&self, data: &[&[u8]], signature: &[u8]) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            let message_digest = match self.algorithm.hash_algorithm {
                HashAlgorithm::SHA256 => MessageDigest::sha256(),
                HashAlgorithm::SHA384 => MessageDigest::sha384(),
                HashAlgorithm::SHA512 => MessageDigest::sha512(),
            };

            let mut signer = Signer::new(message_digest, &self.private_key)?;
            for part in data {
                signer.update(part)?;
            }
            let new_signature = signer.sign_to_vec()?;
            if !memcmp::eq(&new_signature, &signature) {
                bail!("Failed to verify.")
            }
            Ok(())
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Result;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;

    #[test]
    fn sign_and_verify_jwk() -> Result<()> {
        let data = b"abcde12345";

        for name in &[
            "HS256",
            "HS384",
            "HS512",
        ] {
            let alg = HmacJwsAlgorithm::new(name, hash_algorithm(name));

            let private_key = load_file(match *name {
                "HS256" => "jwk/hs256_private.jwk",
                "HS384" => "jwk/hs384_private.jwk",
                "HS512" => "jwk/hs512_private.jwk",
                _ => unreachable!()
            })?;

            let signer = alg.signer_from_jwk(&private_key)?;
            let signature = signer.sign(&[data])?;
            signer.verify(&[data], &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_slice() -> Result<()> {
        let private_key = b"ABCDE12345";
        let data = b"abcde12345";

        for name in &[
            "HS256",
            "HS384",
            "HS512",
        ] {
            let alg = HmacJwsAlgorithm::new(name, hash_algorithm(name));

            let signer = alg.signer_from_slice(private_key)?;
            let signature = signer.sign(&[data])?;
            signer.verify(&[data], &signature)?;
        }

        Ok(())
    }

    fn load_file(path: &str) -> Result<Vec<u8>> {
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push("data");
        pb.push(path);

        let mut file = File::open(&pb)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(data)
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

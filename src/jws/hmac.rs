use anyhow::{anyhow, bail};
use openssl::hash::MessageDigest;
use openssl::memcmp;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use serde_json::{Map, Value};
use std::io::Read;

use crate::error::JoseError;
use crate::jws::util::{json_base64_bytes, json_eq};
use crate::jws::{JwsAlgorithm, JwsSigner, JwsVerifier};

#[derive(Debug, Eq, PartialEq)]
pub enum HmacJwsAlgorithm {
    /// HMAC using SHA-256
    HS256,

    /// HMAC using SHA-384
    HS384,

    /// HMAC using SHA-512
    HS512,
}

impl HmacJwsAlgorithm {
    /// Return a signer from a private key of oct JWK format.
    ///
    /// # Arguments
    /// * `input` - A private key of oct JWK format.
    pub fn signer_from_jwk(&self, input: impl AsRef<[u8]>) -> Result<HmacJwsSigner, JoseError> {
        let key_data = (|| -> anyhow::Result<Vec<u8>> {
            let map: Map<String, Value> = serde_json::from_slice(input.as_ref())?;

            json_eq(&map, "kty", "oct", true)?;
            json_eq(&map, "use", "sig", false)?;
            json_eq(&map, "alg", &self.name(), false)?;
            let key_data = json_base64_bytes(&map, "k")?;

            Ok(key_data)
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))?;

        self.signer_from_slice(&key_data)
    }

    /// Return a signer from a secret key.
    ///
    /// # Arguments
    /// * `data` - A secret key.
    pub fn signer_from_slice(&self, input: impl AsRef<[u8]>) -> Result<HmacJwsSigner, JoseError> {
        PKey::hmac(input.as_ref())
            .map_err(|err| JoseError::InvalidKeyFormat(anyhow!(err)))
            .map(|val| HmacJwsSigner {
                algorithm: &self,
                private_key: val,
            })
    }
}

impl JwsAlgorithm for HmacJwsAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::HS256 => "HS256",
            Self::HS384 => "HS384",
            Self::HS512 => "HS512",
        }
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

    fn sign(&self, message: &mut dyn Read) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let message_digest = match self.algorithm {
                HmacJwsAlgorithm::HS256 => MessageDigest::sha256(),
                HmacJwsAlgorithm::HS384 => MessageDigest::sha384(),
                HmacJwsAlgorithm::HS512 => MessageDigest::sha512(),
            };

            let mut signer = Signer::new(message_digest, &self.private_key)?;

            let mut buf = [0; 1024];
            loop {
                match message.read(&mut buf)? {
                    0 => break,
                    n => signer.update(&buf[..n])?,
                }
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

    fn verify(&self, message: &mut dyn Read, signature: &[u8]) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            let message_digest = match self.algorithm {
                HmacJwsAlgorithm::HS256 => MessageDigest::sha256(),
                HmacJwsAlgorithm::HS384 => MessageDigest::sha384(),
                HmacJwsAlgorithm::HS512 => MessageDigest::sha512(),
            };

            let mut signer = Signer::new(message_digest, &self.private_key)?;

            let mut buf = [0; 1024];
            loop {
                match message.read(&mut buf)? {
                    0 => break,
                    n => signer.update(&buf[..n])?,
                }
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
    use std::io::{Cursor, Read};
    use std::path::PathBuf;

    #[test]
    fn sign_and_verify_hmac_jwk() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            HmacJwsAlgorithm::HS256,
            HmacJwsAlgorithm::HS384,
            HmacJwsAlgorithm::HS512,
        ] {
            let private_key = load_file("jwk/oct_private.jwk")?;

            let signer = alg.signer_from_jwk(&private_key)?;
            let signature = signer.sign(&mut Cursor::new(input))?;
            signer.verify(&mut Cursor::new(input), &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_hmac_bytes() -> Result<()> {
        let private_key = b"ABCDE12345";
        let input = b"abcde12345";

        for alg in &[
            HmacJwsAlgorithm::HS256,
            HmacJwsAlgorithm::HS384,
            HmacJwsAlgorithm::HS512,
        ] {
            let signer = alg.signer_from_slice(private_key)?;
            let signature = signer.sign(&mut Cursor::new(input))?;
            signer.verify(&mut Cursor::new(input), &signature)?;
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
}

use anyhow::bail;
use openssl::hash::MessageDigest;
use openssl::memcmp;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use serde_json::Value;
use std::io::Read;

use crate::error::JoseError;
use crate::jwk::Jwk;
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
    /// * `jwk` - A private key of oct JWK format.
    pub fn signer_from_jwk(&self, jwk: &Jwk) -> Result<HmacJwsSigner, JoseError> {
        (|| -> anyhow::Result<HmacJwsSigner> {
            match jwk.key_type() {
                "oct" => {}
                val => bail!("A parameter kty must be oct: {}", val),
            };
            match jwk.key_use() {
                Some("sig") | None => {}
                Some(val) => bail!("A parameter use must be sig: {}", val),
            };
            match jwk.key_operations() {
                Some(vals) if vals.contains(&"sign") => {}
                None => {}
                _ => bail!("A parameter key_ops must contains sign."),
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }
            let key_id = jwk.key_id();
            let k = match jwk.parameter("k") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(val) => bail!("A parameter k must be string type but {:?}", val),
                None => bail!("A parameter k is required."),
            };

            let private_key = PKey::hmac(&k)?;

            Ok(HmacJwsSigner {
                algorithm: &self,
                private_key,
                key_id: key_id.map(|val| val.to_string()),
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a signer from a secret key.
    ///
    /// # Arguments
    /// * `data` - A secret key.
    pub fn signer_from_slice(&self, input: impl AsRef<[u8]>) -> Result<HmacJwsSigner, JoseError> {
        (|| -> anyhow::Result<HmacJwsSigner> {
            let pkey = PKey::hmac(input.as_ref())?;

            Ok(HmacJwsSigner {
                algorithm: &self,
                private_key: pkey,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a private key of oct JWK format.
    ///
    /// # Arguments
    /// * `jwk` - A secret key of oct JWK format.
    pub fn verifier_from_jwk(&self, jwk: &Jwk) -> Result<HmacJwsVerifier, JoseError> {
        (|| -> anyhow::Result<HmacJwsVerifier> {
            match jwk.key_type() {
                "oct" => {}
                val => bail!("A parameter kty must be oct: {}", val),
            };
            match jwk.key_use() {
                Some("sig") | None => {}
                Some(val) => bail!("A parameter use must be sig: {}", val),
            };
            match jwk.key_operations() {
                Some(vals) if vals.contains(&"verify") => {}
                None => {}
                _ => bail!("A parameter key_ops must contains verify."),
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }
            let key_id = jwk.key_id();
            let k = match jwk.parameter("k") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(val) => bail!("A parameter k must be string type but {:?}", val),
                None => bail!("A parameter k is required."),
            };

            let private_key = PKey::hmac(&k)?;

            Ok(HmacJwsVerifier {
                algorithm: &self,
                private_key,
                key_id: key_id.map(|val| val.to_string()),
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a secret key.
    ///
    /// # Arguments
    /// * `input` - A secret key.
    pub fn verifier_from_slice(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<HmacJwsVerifier, JoseError> {
        (|| -> anyhow::Result<HmacJwsVerifier> {
            let pkey = PKey::hmac(input.as_ref())?;

            Ok(HmacJwsVerifier {
                algorithm: &self,
                private_key: pkey,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
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
    key_id: Option<String>,
}

impl<'a> JwsSigner<HmacJwsAlgorithm> for HmacJwsSigner<'a> {
    fn algorithm(&self) -> &HmacJwsAlgorithm {
        &self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn set_key_id(&mut self, key_id: &str) {
        self.key_id = Some(key_id.to_string());
    }

    fn unset_key_id(&mut self) {
        self.key_id = None;
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

pub struct HmacJwsVerifier<'a> {
    algorithm: &'a HmacJwsAlgorithm,
    private_key: PKey<Private>,
    key_id: Option<String>,
}

impl<'a> JwsVerifier<HmacJwsAlgorithm> for HmacJwsVerifier<'a> {
    fn algorithm(&self) -> &HmacJwsAlgorithm {
        &self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn set_key_id(&mut self, key_id: &str) {
        self.key_id = Some(key_id.to_string());
    }

    fn unset_key_id(&mut self) {
        self.key_id = None;
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
            let private_key = Jwk::from_slice(load_file("jwk/oct_private.jwk")?)?;

            let signer = alg.signer_from_jwk(&private_key)?;
            let signature = signer.sign(&mut Cursor::new(input))?;

            let verifier = alg.verifier_from_jwk(&private_key)?;
            verifier.verify(&mut Cursor::new(input), &signature)?;
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

            let verifier = alg.verifier_from_slice(private_key)?;
            verifier.verify(&mut Cursor::new(input), &signature)?;
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

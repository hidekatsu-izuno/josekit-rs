use std::collections::BTreeSet;
use std::iter::Iterator;

use anyhow::bail;
use openssl::hash::MessageDigest;
use openssl::memcmp;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use serde_json::Value;

use crate::error::JoseError;
use crate::jwk::Jwk;
use crate::jws::{JwsAlgorithm, JwsSigner, JwsVerifier};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum HmacJwsAlgorithm {
    /// HMAC using SHA-256
    HS256,

    /// HMAC using SHA-384
    HS384,

    /// HMAC using SHA-512
    HS512,
}

impl HmacJwsAlgorithm {
    /// Make a JWK encoded oct private key.
    ///
    /// # Arguments
    /// * `secret` - A secret key
    pub fn to_jwk(&self, secret: &[u8]) -> Jwk {
        let k = base64::encode_config(secret, base64::URL_SAFE_NO_PAD);

        let mut jwk = Jwk::new("oct");
        jwk.set_key_use("sig");
        jwk.set_key_operations(vec!["sign", "verify"]);
        jwk.set_algorithm(self.name());
        jwk.set_parameter("k", Some(Value::String(k))).unwrap();

        jwk
    }

    /// Return a signer from a secret key.
    ///
    /// # Arguments
    /// * `data` - A secret key.
    pub fn signer_from_slice(&self, input: impl AsRef<[u8]>) -> Result<HmacJwsSigner, JoseError> {
        (|| -> anyhow::Result<HmacJwsSigner> {
            let pkey = PKey::hmac(input.as_ref())?;

            Ok(HmacJwsSigner {
                algorithm: self.clone(),
                private_key: pkey,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a signer from a secret key that is formatted by a JWK of oct type.
    ///
    /// # Arguments
    /// * `jwk` - A secret key that is formatted by a JWK of oct type.
    pub fn signer_from_jwk(&self, jwk: &Jwk) -> Result<HmacJwsSigner, JoseError> {
        (|| -> anyhow::Result<HmacJwsSigner> {
            match jwk.key_type() {
                val if val == self.key_type() => {}
                val => bail!("A parameter kty must be {}: {}", self.key_type(), val),
            }
            match jwk.key_use() {
                Some(val) if val == "sig" => {}
                None => {}
                Some(val) => bail!("A parameter use must be sig: {}", val),
            }
            match jwk.key_operations() {
                Some(vals) if vals.iter().any(|e| e == "sign") => {}
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
                algorithm: self.clone(),
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

            Ok(HmacJwsVerifier::new(self, pkey, None))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a secret key that is formatted by a JWK of oct type.
    ///
    /// # Arguments
    /// * `jwk` - A secret key that is formatted by a JWK of oct type.
    pub fn verifier_from_jwk(&self, jwk: &Jwk) -> Result<HmacJwsVerifier, JoseError> {
        (|| -> anyhow::Result<HmacJwsVerifier> {
            match jwk.key_type() {
                val if val == self.key_type() => {}
                val => bail!("A parameter kty must be {}: {}", self.key_type(), val),
            }
            match jwk.key_use() {
                Some(val) if val == "sig" => {}
                None => {}
                Some(val) => bail!("A parameter use must be sig: {}", val),
            }
            match jwk.key_operations() {
                Some(vals) if vals.iter().any(|e| e == "verify") => {}
                None => {}
                _ => bail!("A parameter key_ops must contains verify."),
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }

            let k = match jwk.parameter("k") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(val) => bail!("A parameter k must be string type but {:?}", val),
                None => bail!("A parameter k is required."),
            };

            let private_key = PKey::hmac(&k)?;
            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(HmacJwsVerifier::new(self, private_key, key_id))
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

    fn key_type(&self) -> &str {
        "oct"
    }

    fn signature_len(&self) -> usize {
        match self {
            Self::HS256 => 43,
            Self::HS384 => 64,
            Self::HS512 => 86,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HmacJwsSigner {
    algorithm: HmacJwsAlgorithm,
    private_key: PKey<Private>,
    key_id: Option<String>,
}

impl JwsSigner for HmacJwsSigner {
    fn algorithm(&self) -> &dyn JwsAlgorithm {
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

    fn remove_key_id(&mut self) {
        self.key_id = None;
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let message_digest = match self.algorithm {
                HmacJwsAlgorithm::HS256 => MessageDigest::sha256(),
                HmacJwsAlgorithm::HS384 => MessageDigest::sha384(),
                HmacJwsAlgorithm::HS512 => MessageDigest::sha512(),
            };

            let mut signer = Signer::new(message_digest, &self.private_key)?;
            signer.update(message)?;
            let signature = signer.sign_to_vec()?;
            Ok(signature)
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }
}

#[derive(Debug, Clone)]
pub struct HmacJwsVerifier {
    algorithm: HmacJwsAlgorithm,
    private_key: PKey<Private>,
    key_id: Option<String>,
    acceptable_criticals: BTreeSet<String>,
}

impl HmacJwsVerifier {
    fn new(
        algorithm: &HmacJwsAlgorithm,
        private_key: PKey<Private>,
        key_id: Option<String>,
    ) -> Self {
        Self {
            algorithm: algorithm.clone(),
            private_key,
            key_id,
            acceptable_criticals: BTreeSet::new(),
        }
    }
}

impl JwsVerifier for HmacJwsVerifier {
    fn algorithm(&self) -> &dyn JwsAlgorithm {
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

    fn remove_key_id(&mut self) {
        self.key_id = None;
    }

    fn is_acceptable_critical(&self, name: &str) -> bool {
        self.acceptable_criticals.contains(name)
    }

    fn add_acceptable_critical(&mut self, name: &str) {
        self.acceptable_criticals.insert(name.to_string());
    }

    fn remove_acceptable_critical(&mut self, name: &str) {
        self.acceptable_criticals.remove(name);
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            let message_digest = match self.algorithm {
                HmacJwsAlgorithm::HS256 => MessageDigest::sha256(),
                HmacJwsAlgorithm::HS384 => MessageDigest::sha384(),
                HmacJwsAlgorithm::HS512 => MessageDigest::sha512(),
            };

            let mut signer = Signer::new(message_digest, &self.private_key)?;
            signer.update(message)?;
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
    fn sign_and_verify_hmac_generated_jwk() -> Result<()> {
        let input = b"12345abcde";

        for alg in &[
            HmacJwsAlgorithm::HS256,
            HmacJwsAlgorithm::HS384,
            HmacJwsAlgorithm::HS512,
        ] {
            let private_key = alg.to_jwk(input);

            let signer = alg.signer_from_jwk(&private_key)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_jwk(&private_key)?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

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
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_jwk(&private_key)?;
            verifier.verify(input, &signature)?;
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
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_slice(private_key)?;
            verifier.verify(input, &signature)?;
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

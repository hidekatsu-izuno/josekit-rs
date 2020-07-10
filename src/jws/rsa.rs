use anyhow::bail;
use once_cell::sync::Lazy;
use openssl::hash::MessageDigest;
use openssl::pkey::{HasPublic, PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use serde_json::Value;

use crate::der::oid::ObjectIdentifier;
use crate::der::{DerBuilder, DerReader, DerType};
use crate::error::JoseError;
use crate::jwk::Jwk;
use crate::jws::{JwsAlgorithm, JwsSigner, JwsVerifier};
use crate::util::parse_pem;

static OID_RSA_ENCRYPTION: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 1]));

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum RsaJwsAlgorithm {
    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256,

    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384,

    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512,
}

impl RsaJwsAlgorithm {
    /// Return a signer from a private key of common or traditinal PEM format.
    ///
    /// Common PEM format is a DER and base64 encoded PKCS#8 PrivateKeyInfo
    /// that surrounded by "-----BEGIN/END PRIVATE KEY----".
    ///
    /// Traditional PEM format is a DER and base64 encoded PKCS#1 RSAPrivateKey
    /// that surrounded by "-----BEGIN/END RSA PRIVATE KEY----".
    ///
    /// # Arguments
    /// * `input` - A private key of common or traditinal PEM format.
    pub fn signer_from_pem(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<Box<dyn JwsSigner>, JoseError> {
        (|| -> anyhow::Result<Box<dyn JwsSigner>> {
            let (alg, data) = parse_pem(input.as_ref())?;

            let pkey = match alg.as_str() {
                "PRIVATE KEY" => {
                    if !self.detect_pkcs8(&data, false)? {
                        bail!("Invalid PEM contents.");
                    }
                    PKey::private_key_from_der(&data)?
                }
                "RSA PRIVATE KEY" => {
                    let pkcs8 = self.to_pkcs8(&data, false);
                    PKey::private_key_from_der(&pkcs8)?
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };
            self.check_key(&pkey)?;

            Ok(Box::new(RsaJwsSigner {
                algorithm: self.clone(),
                private_key: pkey,
                key_id: None,
            }))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a signer from a private key that is a DER encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey.
    pub fn signer_from_der(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<Box<dyn JwsSigner>, JoseError> {
        (|| -> anyhow::Result<Box<dyn JwsSigner>> {
            let pkcs8;
            let pkcs8_ref = if self.detect_pkcs8(input.as_ref(), false)? {
                input.as_ref()
            } else {
                pkcs8 = self.to_pkcs8(input.as_ref(), false);
                &pkcs8
            };

            let pkey = PKey::private_key_from_der(pkcs8_ref)?;
            self.check_key(&pkey)?;

            Ok(Box::new(RsaJwsSigner {
                algorithm: self.clone(),
                private_key: pkey,
                key_id: None,
            }))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a key of common or traditional PEM format.
    ///
    /// Common PEM format is a DER and base64 encoded SubjectPublicKeyInfo
    /// that surrounded by "-----BEGIN/END PUBLIC KEY----".
    ///
    /// Traditional PEM format is a DER and base64 PKCS#1 RSAPublicKey
    /// that surrounded by "-----BEGIN/END RSA PUBLIC KEY----".
    ///
    /// # Arguments
    /// * `input` - A public key of common or traditional PEM format.
    pub fn verifier_from_pem(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<Box<dyn JwsVerifier>, JoseError> {
        (|| -> anyhow::Result<Box<dyn JwsVerifier>> {
            let (alg, data) = parse_pem(input.as_ref())?;

            let pkey = match alg.as_str() {
                "PUBLIC KEY" => {
                    if !self.detect_pkcs8(&data, true)? {
                        bail!("Invalid PEM contents.");
                    }
                    PKey::public_key_from_der(&data)?
                }
                "RSA PUBLIC KEY" => {
                    let pkcs8 = self.to_pkcs8(&data, true);
                    PKey::public_key_from_der(&pkcs8)?
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };
            self.check_key(&pkey)?;

            Ok(Box::new(RsaJwsVerifier {
                algorithm: self.clone(),
                public_key: pkey,
                key_id: None,
            }))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return the verifier from a public key that is a DER encoded SubjectPublicKeyInfo or PKCS#1 RSAPublicKey.
    ///
    /// # Arguments
    /// * `input` - A public key that is a DER encoded SubjectPublicKeyInfo or PKCS#1 RSAPublicKey.
    pub fn verifier_from_der(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<Box<dyn JwsVerifier>, JoseError> {
        (|| -> anyhow::Result<Box<dyn JwsVerifier>> {
            let pkcs8;
            let pkcs8_ref = if self.detect_pkcs8(input.as_ref(), true)? {
                input.as_ref()
            } else {
                pkcs8 = self.to_pkcs8(input.as_ref(), true);
                &pkcs8
            };

            let pkey = PKey::public_key_from_der(pkcs8_ref)?;
            self.check_key(&pkey)?;

            Ok(Box::new(RsaJwsVerifier {
                algorithm: self.clone(),
                public_key: pkey,
                key_id: None,
            }))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn check_key<T: HasPublic>(&self, pkey: &PKey<T>) -> anyhow::Result<()> {
        let rsa = pkey.rsa()?;

        if rsa.size() * 8 < 2048 {
            bail!("key length must be 2048 or more.");
        }

        Ok(())
    }

    fn detect_pkcs8(&self, input: &[u8], is_public: bool) -> anyhow::Result<bool> {
        let mut reader = DerReader::from_reader(input);

        match reader.next() {
            Ok(Some(DerType::Sequence)) => {}
            _ => return Ok(false),
        }

        {
            if !is_public {
                // Version
                match reader.next() {
                    Ok(Some(DerType::Integer)) => match reader.to_u8() {
                        Ok(val) => {
                            if val != 0 {
                                bail!("Unrecognized version: {}", val);
                            }
                        }
                        _ => return Ok(false),
                    },
                    _ => return Ok(false),
                }
            }

            match reader.next() {
                Ok(Some(DerType::Sequence)) => {}
                _ => return Ok(false),
            }

            {
                match reader.next() {
                    Ok(Some(DerType::ObjectIdentifier)) => match reader.to_object_identifier() {
                        Ok(val) => {
                            if val != *OID_RSA_ENCRYPTION {
                                bail!("Incompatible oid: {}", val);
                            }
                        }
                        _ => return Ok(false),
                    },
                    _ => return Ok(false),
                }

                match reader.next() {
                    Ok(Some(DerType::Null)) => {}
                    _ => return Ok(false),
                }
            }
        }

        Ok(true)
    }

    fn to_pkcs8(&self, input: &[u8], is_public: bool) -> Vec<u8> {
        let mut builder = DerBuilder::new();
        builder.begin(DerType::Sequence);
        {
            if !is_public {
                builder.append_integer_from_u8(0);
            }

            builder.begin(DerType::Sequence);
            {
                builder.append_object_identifier(&OID_RSA_ENCRYPTION);
                builder.append_null();
            }
            builder.end();

            if is_public {
                builder.append_bit_string_from_slice(input, 0);
            } else {
                builder.append_octed_string_from_slice(input);
            }
        }
        builder.end();

        builder.build()
    }
}

impl JwsAlgorithm for RsaJwsAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::RS256 => "RS256",
            Self::RS384 => "RS384",
            Self::RS512 => "RS512",
        }
    }

    fn key_type(&self) -> &str {
        "RSA"
    }

    fn signature_len(&self) -> usize {
        match self {
            Self::RS256 => 342,
            Self::RS384 => 342,
            Self::RS512 => 342,
        }
    }

    fn signer_from_jwk(&self, jwk: &Jwk) -> Result<Box<dyn JwsSigner>, JoseError> {
        (|| -> anyhow::Result<Box<dyn JwsSigner>> {
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

            let n = match jwk.parameter("n") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter n must be a string."),
                None => bail!("A parameter n is required."),
            };
            let e = match jwk.parameter("e") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter e must be a string."),
                None => bail!("A parameter e is required."),
            };
            let d = match jwk.parameter("d") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter d must be a string."),
                None => bail!("A parameter d is required."),
            };
            let p = match jwk.parameter("p") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter p must be a string."),
                None => bail!("A parameter p is required."),
            };
            let q = match jwk.parameter("q") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter q must be a string."),
                None => bail!("A parameter q is required."),
            };
            let dp = match jwk.parameter("dp") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter dp must be a string."),
                None => bail!("A parameter dp is required."),
            };
            let dq = match jwk.parameter("dq") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter dq must be a string."),
                None => bail!("A parameter dq is required."),
            };
            let qi = match jwk.parameter("qi") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter qi must be a string."),
                None => bail!("A parameter qi is required."),
            };

            let mut builder = DerBuilder::new();
            builder.begin(DerType::Sequence);
            {
                builder.append_integer_from_u8(0); // version
                builder.append_integer_from_be_slice(&n, false); // n
                builder.append_integer_from_be_slice(&e, false); // e
                builder.append_integer_from_be_slice(&d, false); // d
                builder.append_integer_from_be_slice(&p, false); // p
                builder.append_integer_from_be_slice(&q, false); // q
                builder.append_integer_from_be_slice(&dp, false); // d mod (p-1)
                builder.append_integer_from_be_slice(&dq, false); // d mod (q-1)
                builder.append_integer_from_be_slice(&qi, false); // (inverse of q) mod p
            }
            builder.end();

            let pkcs8 = self.to_pkcs8(&builder.build(), false);
            let pkey = PKey::private_key_from_der(&pkcs8)?;
            self.check_key(&pkey)?;

            Ok(Box::new(RsaJwsSigner {
                algorithm: self.clone(),
                private_key: pkey,
                key_id: key_id.map(|val| val.to_string()),
            }))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn verifier_from_jwk(&self, jwk: &Jwk) -> Result<Box<dyn JwsVerifier>, JoseError> {
        (|| -> anyhow::Result<Box<dyn JwsVerifier>> {
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
            let key_id = jwk.key_id();

            let n = match jwk.parameter("n") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter n must be a string."),
                None => bail!("A parameter n is required."),
            };
            let e = match jwk.parameter("e") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter e must be a string."),
                None => bail!("A parameter e is required."),
            };

            let mut builder = DerBuilder::new();
            builder.begin(DerType::Sequence);
            {
                builder.append_integer_from_be_slice(&n, false); // n
                builder.append_integer_from_be_slice(&e, false); // e
            }
            builder.end();

            let pkcs8 = self.to_pkcs8(&builder.build(), true);
            let pkey = PKey::public_key_from_der(&pkcs8)?;
            self.check_key(&pkey)?;

            Ok(Box::new(RsaJwsVerifier {
                algorithm: self.clone(),
                public_key: pkey,
                key_id: key_id.map(|val| val.to_string()),
            }))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }
}

pub struct RsaJwsSigner {
    algorithm: RsaJwsAlgorithm,
    private_key: PKey<Private>,
    key_id: Option<String>,
}

impl JwsSigner for RsaJwsSigner {
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
                RsaJwsAlgorithm::RS256 => MessageDigest::sha256(),
                RsaJwsAlgorithm::RS384 => MessageDigest::sha384(),
                RsaJwsAlgorithm::RS512 => MessageDigest::sha512(),
            };

            let mut signer = Signer::new(message_digest, &self.private_key)?;
            signer.update(message)?;
            let signature = signer.sign_to_vec()?;
            Ok(signature)
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }
}

pub struct RsaJwsVerifier {
    algorithm: RsaJwsAlgorithm,
    public_key: PKey<Public>,
    key_id: Option<String>,
}

impl JwsVerifier for RsaJwsVerifier {
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

    fn unset_key_id(&mut self) {
        self.key_id = None;
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            let message_digest = match self.algorithm {
                RsaJwsAlgorithm::RS256 => MessageDigest::sha256(),
                RsaJwsAlgorithm::RS384 => MessageDigest::sha384(),
                RsaJwsAlgorithm::RS512 => MessageDigest::sha512(),
            };

            let mut verifier = Verifier::new(message_digest, &self.public_key)?;
            verifier.update(message)?;
            verifier.verify(signature)?;
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
    fn sign_and_verify_rsa_jwt() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsaJwsAlgorithm::RS256,
            RsaJwsAlgorithm::RS384,
            RsaJwsAlgorithm::RS512,
        ] {
            let private_key = load_file("jwk/RSA_private.jwk")?;
            let public_key = load_file("jwk/RSA_public.jwk")?;

            let signer = alg.signer_from_jwk(&Jwk::from_slice(&private_key)?)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_jwk(&Jwk::from_slice(&public_key)?)?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsa_pkcs8_pem() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsaJwsAlgorithm::RS256,
            RsaJwsAlgorithm::RS384,
            RsaJwsAlgorithm::RS512,
        ] {
            let private_key = load_file("pem/RSA_2048bit_pkcs8_private.pem")?;
            let public_key = load_file("pem/RSA_2048bit_pkcs8_public.pem")?;

            let signer = alg.signer_from_pem(&private_key)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsa_pkcs8_der() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsaJwsAlgorithm::RS256,
            RsaJwsAlgorithm::RS384,
            RsaJwsAlgorithm::RS512,
        ] {
            let private_key = load_file("der/RSA_2048bit_pkcs8_private.der")?;
            let public_key = load_file("der/RSA_2048bit_pkcs8_public.der")?;

            let signer = alg.signer_from_der(&private_key)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_der(&public_key)?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsa_pkcs1_pem() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsaJwsAlgorithm::RS256,
            RsaJwsAlgorithm::RS384,
            RsaJwsAlgorithm::RS512,
        ] {
            let private_key = load_file("pem/RSA_2048bit_private.pem")?;
            let public_key = load_file("pem/RSA_2048bit_public.pem")?;

            let signer = alg.signer_from_pem(&private_key)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsa_pkcs1_der() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsaJwsAlgorithm::RS256,
            RsaJwsAlgorithm::RS384,
            RsaJwsAlgorithm::RS512,
        ] {
            let private_key = load_file("der/RSA_2048bit_private.der")?;
            let public_key = load_file("der/RSA_2048bit_public.der")?;

            let signer = alg.signer_from_der(&private_key)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_der(&public_key)?;
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

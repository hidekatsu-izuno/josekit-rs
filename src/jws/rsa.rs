use anyhow::bail;
use once_cell::sync::Lazy;
use openssl::hash::MessageDigest;
use openssl::pkey::{HasPublic, PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use serde_json::{Map, Value};
use std::io::Read;

use crate::der::oid::ObjectIdentifier;
use crate::der::{DerBuilder, DerReader, DerType};
use crate::error::JoseError;
use crate::util::{json_eq, json_in, json_get, parse_pem};
use crate::jws::{JwsAlgorithm, JwsSigner, JwsVerifier};

static OID_RSA_ENCRYPTION: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 1]));

#[derive(Debug, Eq, PartialEq)]
pub enum RsaJwsAlgorithm {
    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256,

    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384,

    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512,
}

impl RsaJwsAlgorithm {
    /// Return a signer from a private key of RSA JWK format.
    ///
    /// # Arguments
    /// * `input` - A private key of RSA JWK format.
    pub fn signer_from_jwk(&self, input: impl AsRef<[u8]>) -> Result<RsaJwsSigner, JoseError> {
        (|| -> anyhow::Result<RsaJwsSigner> {
            let map: Map<String, Value> = serde_json::from_slice(input.as_ref())?;

            let kid = json_get(&map, "kid", false)?;
            json_eq(&map, "kty", "RSA", true)?;
            json_eq(&map, "use", "sig", false)?;
            json_in(&map, "key_ops", "sign", false)?;
            json_eq(&map, "alg", self.name(), false)?;
            let n = base64::decode_config(json_get(&map, "n", true)?.unwrap(), base64::URL_SAFE_NO_PAD)?;
            let e = base64::decode_config(json_get(&map, "e", true)?.unwrap(), base64::URL_SAFE_NO_PAD)?;
            let d = base64::decode_config(json_get(&map, "d", true)?.unwrap(), base64::URL_SAFE_NO_PAD)?;
            let p = base64::decode_config(json_get(&map, "p", true)?.unwrap(), base64::URL_SAFE_NO_PAD)?;
            let q = base64::decode_config(json_get(&map, "q", true)?.unwrap(), base64::URL_SAFE_NO_PAD)?;
            let dp = base64::decode_config(json_get(&map, "dp", true)?.unwrap(), base64::URL_SAFE_NO_PAD)?;
            let dq = base64::decode_config(json_get(&map, "dq", true)?.unwrap(), base64::URL_SAFE_NO_PAD)?;
            let qi = base64::decode_config(json_get(&map, "qi", true)?.unwrap(), base64::URL_SAFE_NO_PAD)?;

            let mut builder = DerBuilder::new();
            builder.begin(DerType::Sequence);
            {
                builder.append_integer_from_u8(0); // version
                builder.append_integer_from_be_slice(&n); // n
                builder.append_integer_from_be_slice(&e); // e
                builder.append_integer_from_be_slice(&d); // d
                builder.append_integer_from_be_slice(&p); // p
                builder.append_integer_from_be_slice(&q); // q
                builder.append_integer_from_be_slice(&dp); // d mod (p-1)
                builder.append_integer_from_be_slice(&dq); // d mod (q-1)
                builder.append_integer_from_be_slice(&qi); // (inverse of q) mod p
            }
            builder.end();

            let pkcs8 = self.to_pkcs8(&builder.build(), false);
            let pkey = PKey::private_key_from_der(&pkcs8)?;
            self.check_key(&pkey)?;

            Ok(RsaJwsSigner {
                algorithm: &self,
                private_key: pkey,
                key_id: kid.map(|val| val.to_string()),
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

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
    pub fn signer_from_pem(&self, input: impl AsRef<[u8]>) -> Result<RsaJwsSigner, JoseError> {
        (|| -> anyhow::Result<RsaJwsSigner> {
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

            Ok(RsaJwsSigner {
                algorithm: &self,
                private_key: pkey,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a signer from a private key that is a DER encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey.
    pub fn signer_from_der(&self, input: impl AsRef<[u8]>) -> Result<RsaJwsSigner, JoseError> {
        (|| -> anyhow::Result<RsaJwsSigner> {
            let pkcs8;
            let pkcs8_ref = if self.detect_pkcs8(input.as_ref(), false)? {
                input.as_ref()
            } else {
                pkcs8 = self.to_pkcs8(input.as_ref(), false);
                &pkcs8
            };

            let pkey = PKey::private_key_from_der(pkcs8_ref)?;
            self.check_key(&pkey)?;

            Ok(RsaJwsSigner {
                algorithm: &self,
                private_key: pkey,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a key of RSA JWK format.
    ///
    /// # Arguments
    /// * `input` - A key of RSA JWK format.
    pub fn verifier_from_jwk(&self, input: impl AsRef<[u8]>) -> Result<RsaJwsVerifier, JoseError> {
        (|| -> anyhow::Result<RsaJwsVerifier> {
            let map: Map<String, Value> = serde_json::from_slice(input.as_ref())?;

            let kid = json_get(&map, "kid", false)?;
            json_eq(&map, "kty", "RSA", true)?;
            json_eq(&map, "use", "sig", false)?;
            json_in(&map, "key_ops", "verify", false)?;
            json_eq(&map, "alg", &self.name(), false)?;
            let n = base64::decode_config(json_get(&map, "n", true)?.unwrap(), base64::URL_SAFE_NO_PAD)?;
            let e = base64::decode_config(json_get(&map, "e", true)?.unwrap(), base64::URL_SAFE_NO_PAD)?;

            let mut builder = DerBuilder::new();
            builder.begin(DerType::Sequence);
            {
                builder.append_integer_from_be_slice(&n); // n
                builder.append_integer_from_be_slice(&e); // e
            }
            builder.end();

            let pkcs8 = self.to_pkcs8(&builder.build(), true);
            let pkey = PKey::public_key_from_der(&pkcs8)?;
            self.check_key(&pkey)?;

            Ok(RsaJwsVerifier {
                algorithm: &self,
                public_key: pkey,
                key_id: kid.map(|val| val.to_string()),
            })
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
    pub fn verifier_from_pem(&self, input: impl AsRef<[u8]>) -> Result<RsaJwsVerifier, JoseError> {
        (|| -> anyhow::Result<RsaJwsVerifier> {
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

            Ok(RsaJwsVerifier {
                algorithm: &self,
                public_key: pkey,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a public key that is a DER encoded SubjectPublicKeyInfo or PKCS#1 RSAPublicKey.
    ///
    /// # Arguments
    /// * `input` - A public key that is a DER encoded SubjectPublicKeyInfo or PKCS#1 RSAPublicKey.
    pub fn verifier_from_der(&self, input: impl AsRef<[u8]>) -> Result<RsaJwsVerifier, JoseError> {
        (|| -> anyhow::Result<RsaJwsVerifier> {
            let pkcs8;
            let pkcs8_ref = if self.detect_pkcs8(input.as_ref(), true)? {
                input.as_ref()
            } else {
                pkcs8 = self.to_pkcs8(input.as_ref(), true);
                &pkcs8
            };

            let pkey = PKey::public_key_from_der(pkcs8_ref)?;
            self.check_key(&pkey)?;

            Ok(RsaJwsVerifier {
                algorithm: &self,
                public_key: pkey,
                key_id: None,
            })
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
        let mut reader = DerReader::new(input.bytes());

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
}

pub struct RsaJwsSigner<'a> {
    algorithm: &'a RsaJwsAlgorithm,
    private_key: PKey<Private>,
    key_id: Option<String>,
}

impl<'a> JwsSigner<RsaJwsAlgorithm> for RsaJwsSigner<'a> {
    fn algorithm(&self) -> &RsaJwsAlgorithm {
        &self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None
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
                RsaJwsAlgorithm::RS256 => MessageDigest::sha256(),
                RsaJwsAlgorithm::RS384 => MessageDigest::sha384(),
                RsaJwsAlgorithm::RS512 => MessageDigest::sha512(),
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

pub struct RsaJwsVerifier<'a> {
    algorithm: &'a RsaJwsAlgorithm,
    public_key: PKey<Public>,
    key_id: Option<String>,
}

impl<'a> JwsVerifier<RsaJwsAlgorithm> for RsaJwsVerifier<'a> {
    fn algorithm(&self) -> &RsaJwsAlgorithm {
        &self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None
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
                RsaJwsAlgorithm::RS256 => MessageDigest::sha256(),
                RsaJwsAlgorithm::RS384 => MessageDigest::sha384(),
                RsaJwsAlgorithm::RS512 => MessageDigest::sha512(),
            };

            let mut verifier = Verifier::new(message_digest, &self.public_key)?;

            let mut buf = [0; 1024];
            loop {
                match message.read(&mut buf)? {
                    0 => break,
                    n => verifier.update(&buf[..n])?,
                }
            }

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
    use std::io::{Cursor, Read};
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

            let signer = alg.signer_from_jwk(&private_key)?;
            let signature = signer.sign(&mut Cursor::new(input))?;

            let verifier = alg.verifier_from_jwk(&public_key)?;
            verifier.verify(&mut Cursor::new(input), &signature)?;
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
            let signature = signer.sign(&mut Cursor::new(input))?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            verifier.verify(&mut Cursor::new(input), &signature)?;
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
            let signature = signer.sign(&mut Cursor::new(input))?;

            let verifier = alg.verifier_from_der(&public_key)?;
            verifier.verify(&mut Cursor::new(input), &signature)?;
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
            let signature = signer.sign(&mut Cursor::new(input))?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            verifier.verify(&mut Cursor::new(input), &signature)?;
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
            let signature = signer.sign(&mut Cursor::new(input))?;

            let verifier = alg.verifier_from_der(&public_key)?;
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

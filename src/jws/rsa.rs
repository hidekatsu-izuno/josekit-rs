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
use crate::jws::util::{json_base64_bytes, json_eq, parse_pem};
use crate::jws::{JwsAlgorithm, JwsSigner, JwsVerifier};

/// RSASSA-PKCS1-v1_5 using SHA-256
pub const RS256: RsaJwsAlgorithm = RsaJwsAlgorithm::new("RS256");

/// RSASSA-PKCS1-v1_5 using SHA-384
pub const RS384: RsaJwsAlgorithm = RsaJwsAlgorithm::new("RS384");

/// RSASSA-PKCS1-v1_5 using SHA-512
pub const RS512: RsaJwsAlgorithm = RsaJwsAlgorithm::new("RS512");

static OID_RSA_ENCRYPTION: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 1]));

#[derive(Debug, Eq, PartialEq)]
pub struct RsaJwsAlgorithm {
    name: &'static str,
}

impl RsaJwsAlgorithm {
    /// Return a new instance.
    ///
    /// # Arguments
    /// * `name` - A algrithm name.
    const fn new(name: &'static str) -> Self {
        RsaJwsAlgorithm { name }
    }

    /// Return a signer from a private key of JWK format.
    ///
    /// # Arguments
    /// * `input` - A private key of JWK format.
    pub fn signer_from_jwk<'a>(
        &'a self,
        input: &[u8],
    ) -> Result<impl JwsSigner<Self> + 'a, JoseError> {
        (|| -> anyhow::Result<RsaJwsSigner> {
            let map: Map<String, Value> = serde_json::from_slice(input)?;

            json_eq(&map, "alg", self.name(), false)?;
            json_eq(&map, "kty", "RSA", true)?;
            json_eq(&map, "use", "sig", false)?;
            let n = json_base64_bytes(&map, "n")?;
            let e = json_base64_bytes(&map, "e")?;
            let d = json_base64_bytes(&map, "d")?;
            let p = json_base64_bytes(&map, "p")?;
            let q = json_base64_bytes(&map, "q")?;
            let dp = json_base64_bytes(&map, "dp")?;
            let dq = json_base64_bytes(&map, "dq")?;
            let qi = json_base64_bytes(&map, "qi")?;

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
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a signer from a private key of PKCS#1 or PKCS#8 PEM format.
    ///
    /// # Arguments
    /// * `input` - A private key of PKCS#1 or PKCS#8 PEM format.
    pub fn signer_from_pem<'a>(
        &'a self,
        input: &[u8],
    ) -> Result<impl JwsSigner<Self> + 'a, JoseError> {
        (|| -> anyhow::Result<RsaJwsSigner> {
            let (alg, data) = parse_pem(input)?;

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
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a signer from a private key of PKCS#1 or PKCS#8 DER format.
    ///
    /// # Arguments
    /// * `input` - A private key of PKCS#1 or PKCS#8 DER format.
    pub fn signer_from_der<'a>(
        &'a self,
        input: &'a [u8],
    ) -> Result<impl JwsSigner<Self> + 'a, JoseError> {
        (|| -> anyhow::Result<RsaJwsSigner> {
            let pkey = if self.detect_pkcs8(input, false)? {
                PKey::private_key_from_der(input)?
            } else {
                let pkcs8 = self.to_pkcs8(input, false);
                PKey::private_key_from_der(&pkcs8)?
            };
            self.check_key(&pkey)?;

            Ok(RsaJwsSigner {
                algorithm: &self,
                private_key: pkey,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a key of JWK format.
    ///
    /// # Arguments
    /// * `input` - A key of JWK format.
    pub fn verifier_from_jwk<'a>(
        &'a self,
        input: &[u8],
    ) -> Result<impl JwsVerifier<Self> + 'a, JoseError> {
        (|| -> anyhow::Result<RsaJwsVerifier> {
            let map: Map<String, Value> = serde_json::from_slice(input)?;

            json_eq(&map, "alg", &self.name(), false)?;
            json_eq(&map, "kty", "RSA", true)?;
            json_eq(&map, "use", "sig", false)?;
            let n = json_base64_bytes(&map, "n")?;
            let e = json_base64_bytes(&map, "e")?;

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
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a public key of PKCS#1 or PKCS#8 PEM format.
    ///
    /// # Arguments
    /// * `input` - A public key of PKCS#1 or PKCS#8 PEM format.
    pub fn verifier_from_pem<'a>(
        &'a self,
        input: &[u8],
    ) -> Result<impl JwsVerifier<Self> + 'a, JoseError> {
        (|| -> anyhow::Result<RsaJwsVerifier> {
            let (alg, data) = parse_pem(input)?;

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
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a public key of PKCS#1 or PKCS#8 DER format.
    ///
    /// # Arguments
    /// * `input` - A public key of PKCS#1 or PKCS#8 DER format.
    pub fn verifier_from_der<'a>(
        &'a self,
        input: &[u8],
    ) -> Result<impl JwsVerifier<Self> + 'a, JoseError> {
        (|| -> anyhow::Result<RsaJwsVerifier> {
            let pkey = if self.detect_pkcs8(input, true)? {
                PKey::public_key_from_der(input)?
            } else {
                let pkcs8 = self.to_pkcs8(input, true);
                PKey::public_key_from_der(&pkcs8)?
            };
            self.check_key(&pkey)?;

            Ok(RsaJwsVerifier {
                algorithm: &self,
                public_key: pkey,
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
        }

        if is_public {
            builder.append_bit_string_from_slice(input, 0);
        } else {
            builder.append_octed_string_from_slice(input);
        }

        builder.end();
        builder.build()
    }
}

impl JwsAlgorithm for RsaJwsAlgorithm {
    fn name(&self) -> &str {
        self.name
    }
}

pub struct RsaJwsSigner<'a> {
    algorithm: &'a RsaJwsAlgorithm,
    private_key: PKey<Private>,
}

impl<'a> JwsSigner<RsaJwsAlgorithm> for RsaJwsSigner<'a> {
    fn algorithm(&self) -> &RsaJwsAlgorithm {
        &self.algorithm
    }

    fn sign(&self, input: &[&[u8]]) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let message_digest = match self.algorithm.name {
                "RS256" => MessageDigest::sha256(),
                "RS384" => MessageDigest::sha384(),
                "RS512" => MessageDigest::sha512(),
                _ => unreachable!(),
            };

            let mut signer = Signer::new(message_digest, &self.private_key)?;
            for part in input {
                signer.update(part)?;
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
}

impl<'a> JwsVerifier<RsaJwsAlgorithm> for RsaJwsVerifier<'a> {
    fn algorithm(&self) -> &RsaJwsAlgorithm {
        &self.algorithm
    }

    fn verify(&self, input: &[&[u8]], signature: &[u8]) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            let message_digest = match self.algorithm.name {
                "RS256" => MessageDigest::sha256(),
                "RS384" => MessageDigest::sha384(),
                "RS512" => MessageDigest::sha512(),
                _ => unreachable!(),
            };

            let mut verifier = Verifier::new(message_digest, &self.public_key)?;
            for part in input {
                verifier.update(part)?;
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
    use std::io::Read;
    use std::path::PathBuf;

    #[test]
    fn sign_and_verify_rsa_jwt() -> Result<()> {
        let data = b"abcde12345";

        for name in &["RS256", "RS384", "RS512"] {
            let alg = RsaJwsAlgorithm::new(name);

            let private_key = load_file("jwk/RSA_private.jwk")?;
            let public_key = load_file("jwk/RSA_public.jwk")?;

            let signer = alg.signer_from_jwk(&private_key)?;
            let signature = signer.sign(&[data])?;

            let verifier = alg.verifier_from_jwk(&public_key)?;
            verifier.verify(&[data], &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsa_pkcs8_pem() -> Result<()> {
        let data = b"abcde12345";

        for name in &["RS256", "RS384", "RS512"] {
            let alg = RsaJwsAlgorithm::new(name);

            let private_key = load_file("pem/rsa_2048_pkcs8_private.pem")?;
            let public_key = load_file("pem/rsa_2048_pkcs8_public.pem")?;

            let signer = alg.signer_from_pem(&private_key)?;
            let signature = signer.sign(&[data])?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            verifier.verify(&[data], &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsa_pkcs8_der() -> Result<()> {
        let data = b"abcde12345";

        for name in &["RS256", "RS384", "RS512"] {
            let alg = RsaJwsAlgorithm::new(name);

            let private_key = load_file("der/rsa_2048_pkcs8_private.der")?;
            let public_key = load_file("der/rsa_2048_pkcs8_public.der")?;

            let signer = alg.signer_from_der(&private_key)?;
            let signature = signer.sign(&[data])?;

            let verifier = alg.verifier_from_der(&public_key)?;
            verifier.verify(&[data], &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsa_pkcs1_pem() -> Result<()> {
        let data = b"abcde12345";

        for name in &["RS256", "RS384", "RS512"] {
            let alg = RsaJwsAlgorithm::new(name);

            let private_key = load_file("pem/rsa_2048_pkcs1_private.pem")?;
            let public_key = load_file("pem/rsa_2048_pkcs1_public.pem")?;

            let signer = alg.signer_from_pem(&private_key)?;
            let signature = signer.sign(&[data])?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            verifier.verify(&[data], &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsa_pkcs1_der() -> Result<()> {
        let data = b"abcde12345";

        for name in &["RS256", "RS384", "RS512"] {
            let alg = RsaJwsAlgorithm::new(name);

            let private_key = load_file("der/rsa_2048_pkcs1_private.der")?;
            let public_key = load_file("der/rsa_2048_pkcs1_public.der")?;

            let signer = alg.signer_from_der(&private_key)?;
            let signature = signer.sign(&[data])?;

            let verifier = alg.verifier_from_der(&public_key)?;
            verifier.verify(&[data], &signature)?;
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

use anyhow::bail;
use once_cell::sync::Lazy;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use serde_json::{Map, Value};
use std::io::Read;

use crate::der::oid::ObjectIdentifier;
use crate::der::{DerBuilder, DerReader, DerType};
use crate::error::JoseError;
use crate::jws::util::{json_base64_bytes, json_eq, parse_pem};
use crate::jws::{JwsAlgorithm, JwsSigner, JwsVerifier};

/// EdDSA
pub const EDDSA: EddsaJwsAlgorithm = EddsaJwsAlgorithm::new("EdDSA");

static OID_ED25519: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 101, 112]));


#[derive(Debug, Eq, PartialEq)]
pub struct EddsaJwsAlgorithm {
    name: &'static str,
}

impl EddsaJwsAlgorithm {
    /// Return a new instance.
    ///
    /// # Arguments
    /// * `name` - A algrithm name.
    /// * `hash_algorithm` - A algrithm name.
    const fn new(name: &'static str) -> Self {
        EddsaJwsAlgorithm { name }
    }

    /// Return a signer from a private key of JWK format.
    ///
    /// # Arguments
    /// * `input` - A private key of JWK format.
    pub fn signer_from_jwk<'a>(
        &'a self,
        input: &[u8],
    ) -> Result<impl JwsSigner<EddsaJwsAlgorithm> + 'a, JoseError> {
        (|| -> anyhow::Result<EddsaJwsSigner> {
            let map: Map<String, Value> = serde_json::from_slice(input)?;

            json_eq(&map, "alg", &self.name(), false)?;
            json_eq(&map, "kty", "OKP", true)?;
            json_eq(&map, "use", "sig", false)?;
            json_eq(&map, "crv", "Ed25519", true)?;
            let d = json_base64_bytes(&map, "d")?;

            let mut builder = DerBuilder::new();
            builder.append_octed_string_from_slice(&d);
            let pkcs8 = self.to_pkcs8(&builder.build(), false);

            let pkey = PKey::private_key_from_der(&pkcs8)?;

            Ok(EddsaJwsSigner {
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
        (|| -> anyhow::Result<EddsaJwsSigner> {
            let (alg, data) = parse_pem(input)?;
            let pkey = match alg.as_str() {
                "PRIVATE KEY" | "X25519 PRIVATE KEY" => {
                    if !self.detect_pkcs8(&data, false)? {
                        bail!("Invalid PEM contents.");
                    }
                    PKey::private_key_from_der(&data)?
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };

            Ok(EddsaJwsSigner {
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
        input: &[u8],
    ) -> Result<impl JwsSigner<Self> + 'a, JoseError> {
        (|| -> anyhow::Result<EddsaJwsSigner> {
            let pkcs8;
            let pkcs8_ref = if self.detect_pkcs8(input, false)? {
                input
            } else {
                pkcs8 = self.to_pkcs8(input, false);
                &pkcs8
            };

            let pkey = PKey::private_key_from_der(pkcs8_ref)?;

            Ok(EddsaJwsSigner {
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
        (|| -> anyhow::Result<EddsaJwsVerifier> {
            let map: Map<String, Value> = serde_json::from_slice(input)?;

            json_eq(&map, "alg", &self.name(), false)?;
            json_eq(&map, "kty", "EC", true)?;
            json_eq(&map, "use", "sig", false)?;
            json_eq(&map, "crv", "Ed25519", true)?;
            let x = json_base64_bytes(&map, "x")?;

            let pkcs8 = self.to_pkcs8(&x, true);
            let pkey = PKey::public_key_from_der(&pkcs8)?;

            Ok(EddsaJwsVerifier {
                algorithm: &self,
                public_key: pkey,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a key of PKCS#8 PEM format.
    ///
    /// # Arguments
    /// * `input` - A key of PKCS#8 PEM format.
    pub fn verifier_from_pem<'a>(
        &'a self,
        input: &[u8],
    ) -> Result<impl JwsVerifier<Self> + 'a, JoseError> {
        (|| -> anyhow::Result<EddsaJwsVerifier> {
            let (alg, data) = parse_pem(input)?;
            let pkey = match alg.as_str() {
                "PUBLIC KEY" | "X25519 PUBLIC KEY" => {
                    if !self.detect_pkcs8(&data, false)? {
                        bail!("Invalid PEM contents.");
                    }
                    PKey::public_key_from_der(&data)?
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };

            Ok(EddsaJwsVerifier {
                algorithm: &self,
                public_key: pkey,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a key of PKCS#8 DER format.
    ///
    /// # Arguments
    /// * `input` - A key of PKCS#8 DER format.
    pub fn verifier_from_der<'a>(
        &'a self,
        input: &[u8],
    ) -> Result<impl JwsVerifier<Self> + 'a, JoseError> {
        (|| -> anyhow::Result<EddsaJwsVerifier> {
            let pkcs8;
            let pkcs8_ref = if self.detect_pkcs8(input, true)? {
                input
            } else {
                pkcs8 = self.to_pkcs8(input, true);
                &pkcs8
            };

            let pkey = PKey::public_key_from_der(pkcs8_ref)?;

            Ok(EddsaJwsVerifier {
                algorithm: &self,
                public_key: pkey,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
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
                            if val != *OID_ED25519 {
                                bail!("Incompatible oid: {}", val);
                            }
                        }
                        _ => return Ok(false),
                    },
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
                builder.append_object_identifier(&OID_ED25519);
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

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let mut signer = Signer::new_without_digest(&self.private_key)?;
            signer.update(message)?;
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

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            let mut verifier = Verifier::new_without_digest(&self.public_key)?;
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
    fn sign_and_verify_eddsa_jwt() -> Result<()> {
        let input = b"abcde12345";

        let alg = EDDSA;

        let private_key = load_file("jwk/OKP_Ed25519_private.jwk")?;
        let public_key = load_file("jwk/OKP_Ed25519_private.jwk")?;

        let signer = alg.signer_from_jwk(&private_key)?;
        let signature = signer.sign(input)?;

        let verifier = alg.verifier_from_jwk(&public_key)?;
        verifier.verify(input, &signature)?;

        Ok(())
    }

    #[test]
    fn sign_and_verify_eddsa_pkcs8_pem() -> Result<()> {
        let input = b"abcde12345";

        let alg = EDDSA;

        let private_key = load_file("pem/eddsa_pkcs8_private.pem")?;
        let public_key = load_file("pem/eddsa_pkcs8_public.pem")?;

        let signer = alg.signer_from_jwk(&private_key)?;
        let signature = signer.sign(input)?;

        let verifier = alg.verifier_from_jwk(&public_key)?;
        verifier.verify(input, &signature)?;

        Ok(())
    }

    #[test]
    fn sign_and_verify_eddsa_pkcs8_der() -> Result<()> {
        let input = b"abcde12345";

        let alg = EDDSA;

        let private_key = load_file("der/eddsa_pkcs8_private.der")?;
        let public_key = load_file("der/eddsa_pkcs8_public.der")?;

        let signer = alg.signer_from_jwk(&private_key)?;
        let signature = signer.sign(input)?;

        let verifier = alg.verifier_from_jwk(&public_key)?;
        verifier.verify(input, &signature)?;

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

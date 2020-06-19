use anyhow::bail;
use once_cell::sync::Lazy;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use serde_json::{Map, Value};
use std::io::Read;

use crate::der::oid::ObjectIdentifier;
use crate::der::{DerBuilder, DerClass, DerReader, DerType};
use crate::error::JoseError;
use crate::jws::util::{json_base64_bytes, json_eq, parse_pem};
use crate::jws::{JwsAlgorithm, JwsSigner, JwsVerifier};

/// ECDSA using P-256 and SHA-256
pub const ES256: EcdsaJwsAlgorithm = EcdsaJwsAlgorithm::new("ES256");

/// ECDSA using P-384 and SHA-384
pub const ES384: EcdsaJwsAlgorithm = EcdsaJwsAlgorithm::new("ES384");

/// ECDSA using P-521 and SHA-512
pub const ES512: EcdsaJwsAlgorithm = EcdsaJwsAlgorithm::new("ES512");

// ECDSA using secp256k1 curve and SHA-256
pub const ES256K: EcdsaJwsAlgorithm = EcdsaJwsAlgorithm::new("ES256K");

static OID_ID_EC_PUBLIC_KEY: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 2, 1]));

static OID_PRIME256V1: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 3, 1, 7]));

static OID_SECP384R1: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 132, 0, 34]));

static OID_SECP521R1: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 132, 0, 35]));

static OID_SECP256K1: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 132, 0, 10]));

#[derive(Debug, Eq, PartialEq)]
pub struct EcdsaJwsAlgorithm {
    name: &'static str,
}

impl EcdsaJwsAlgorithm {
    /// Return a new instance.
    ///
    /// # Arguments
    /// * `name` - A algrithm name.
    const fn new(name: &'static str) -> Self {
        EcdsaJwsAlgorithm { name }
    }

    /// Return a signer from a private key of JWK format.
    ///
    /// # Arguments
    /// * `input` - A private key of JWK format.
    pub fn signer_from_jwk<'a>(
        &'a self,
        input: &[u8],
    ) -> Result<impl JwsSigner<EcdsaJwsAlgorithm> + 'a, JoseError> {
        (|| -> anyhow::Result<EcdsaJwsSigner> {
            let map: Map<String, Value> = serde_json::from_slice(input)?;

            json_eq(&map, "kty", "EC", true)?;
            json_eq(&map, "use", "sig", false)?;
            json_eq(&map, "alg", self.name(), false)?;
            json_eq(&map, "crv", self.curve_name(), true)?;
            let d = json_base64_bytes(&map, "d")?;
            let x = json_base64_bytes(&map, "x")?;
            let y = json_base64_bytes(&map, "y")?;

            let mut builder = DerBuilder::new();
            builder.begin(DerType::Sequence);
            {
                builder.append_integer_from_u8(1);
                builder.append_octed_string_from_slice(&d);
                builder.begin(DerType::Other(DerClass::ContextSpecific, 0));
                {
                    builder.append_object_identifier(self.curve());
                }
                builder.end();
                builder.begin(DerType::Other(DerClass::ContextSpecific, 1));
                {
                    let mut vec = Vec::with_capacity(x.len() + y.len());
                    vec.push(0x04);
                    vec.extend_from_slice(&x);
                    vec.extend_from_slice(&y);
                    builder.append_bit_string_from_slice(&vec, 0);
                }
                builder.end();
            }
            builder.end();

            let pkcs8 = self.to_pkcs8(&builder.build(), false);
            let pkey = PKey::private_key_from_der(&pkcs8)?;

            Ok(EcdsaJwsSigner {
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
        (|| -> anyhow::Result<EcdsaJwsSigner> {
            let (alg, data) = parse_pem(input)?;
            let pkey = match alg.as_str() {
                "PRIVATE KEY" => {
                    if !self.detect_pkcs8(&data, false)? {
                        bail!("Invalid PEM contents.");
                    }
                    PKey::private_key_from_der(&data)?
                }
                "EC PRIVATE KEY" => {
                    let pkcs8 = self.to_pkcs8(&data, false);
                    PKey::private_key_from_der(&pkcs8)?
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };

            Ok(EcdsaJwsSigner {
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
        (|| -> anyhow::Result<EcdsaJwsSigner> {
            let pkey = if self.detect_pkcs8(input, false)? {
                PKey::private_key_from_der(input)?
            } else {
                let pkcs8 = self.to_pkcs8(input, false);
                PKey::private_key_from_der(&pkcs8)?
            };

            Ok(EcdsaJwsSigner {
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
        (|| -> anyhow::Result<EcdsaJwsVerifier> {
            let map: Map<String, Value> = serde_json::from_slice(input)?;

            json_eq(&map, "kty", "EC", true)?;
            json_eq(&map, "use", "sig", false)?;
            json_eq(&map, "alg", self.name(), false)?;
            json_eq(&map, "crv", self.curve_name(), true)?;
            let x = json_base64_bytes(&map, "x")?;
            let y = json_base64_bytes(&map, "y")?;

            let mut vec = Vec::with_capacity(x.len() + y.len());
            vec.push(0x04);
            vec.extend_from_slice(&x);
            vec.extend_from_slice(&y);

            let pkcs8 = self.to_pkcs8(&vec, true);
            let pkey = PKey::public_key_from_der(&pkcs8)?;

            Ok(EcdsaJwsVerifier {
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
        (|| -> anyhow::Result<EcdsaJwsVerifier> {
            let (alg, data) = parse_pem(input)?;

            let pkey = match alg.as_str() {
                "PUBLIC KEY" => {
                    if !self.detect_pkcs8(&data, true)? {
                        bail!("Invalid PEM contents.");
                    }
                    PKey::public_key_from_der(&data)?
                }
                "EC PUBLIC KEY" => {
                    let pkcs8 = self.to_pkcs8(&data, true);
                    PKey::public_key_from_der(&pkcs8)?
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };

            Ok(EcdsaJwsVerifier {
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
        (|| -> anyhow::Result<EcdsaJwsVerifier> {
            let pkey = if self.detect_pkcs8(input, true)? {
                PKey::public_key_from_der(input)?
            } else {
                let pkcs8 = self.to_pkcs8(input, true);
                PKey::public_key_from_der(&pkcs8)?
            };

            Ok(EcdsaJwsVerifier {
                algorithm: &self,
                public_key: pkey,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn curve_name(&self) -> &str {
        match self.name {
            "ES256" => "P-256",
            "ES384" => "P-384",
            "ES512" => "P-521",
            "ES256K" => "secp256k1",
            _ => unreachable!(),
        }
    }

    fn curve(&self) -> &ObjectIdentifier {
        match self.name {
            "ES256" => &*OID_PRIME256V1,
            "ES384" => &*OID_SECP384R1,
            "ES512" => &*OID_SECP521R1,
            "ES256K" => &*OID_SECP256K1,
            _ => unreachable!(),
        }
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
                            if val != *OID_ID_EC_PUBLIC_KEY {
                                bail!("Incompatible oid: {}", val);
                            }
                        }
                        _ => return Ok(false),
                    },
                    _ => return Ok(false),
                }

                match reader.next() {
                    Ok(Some(DerType::ObjectIdentifier)) => match reader.to_object_identifier() {
                        Ok(val) => {
                            if &val != self.curve() {
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
                builder.append_object_identifier(&OID_ID_EC_PUBLIC_KEY);
                builder.append_object_identifier(self.curve());
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

impl JwsAlgorithm for EcdsaJwsAlgorithm {
    fn name(&self) -> &str {
        self.name
    }
}

pub struct EcdsaJwsSigner<'a> {
    algorithm: &'a EcdsaJwsAlgorithm,
    private_key: PKey<Private>,
}

impl<'a> JwsSigner<EcdsaJwsAlgorithm> for EcdsaJwsSigner<'a> {
    fn algorithm(&self) -> &EcdsaJwsAlgorithm {
        &self.algorithm
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let message_digest = match self.algorithm.name {
                "ES256" | "ES256K" => MessageDigest::sha256(),
                "ES384" => MessageDigest::sha384(),
                "ES512" => MessageDigest::sha512(),
                _ => unreachable!(),
            };

            let mut signer = Signer::new(message_digest, &self.private_key)?;
            signer.update(message)?;
            let signature = signer.sign_to_vec()?;
            Ok(signature)
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }
}

pub struct EcdsaJwsVerifier<'a> {
    algorithm: &'a EcdsaJwsAlgorithm,
    public_key: PKey<Public>,
}

impl<'a> JwsVerifier<EcdsaJwsAlgorithm> for EcdsaJwsVerifier<'a> {
    fn algorithm(&self) -> &EcdsaJwsAlgorithm {
        &self.algorithm
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            let message_digest = match self.algorithm.name {
                "ES256" | "ES256K" => MessageDigest::sha256(),
                "ES384" => MessageDigest::sha384(),
                "ES512" => MessageDigest::sha512(),
                _ => unreachable!(),
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
    fn sign_and_verify_ecdsa_jwt() -> Result<()> {
        let input = b"abcde12345";

        for name in &["ES256", "ES384", "ES512", "ES256K"] {
            let alg = EcdsaJwsAlgorithm::new(name);

            let private_key = load_file(match *name {
                "ES256" => "jwk/EC_P-256_private.jwk",
                "ES384" => "jwk/EC_P-384_private.jwk",
                "ES512" => "jwk/EC_P-521_private.jwk",
                "ES256K" => "jwk/EC_secp256k1_private.jwk",
                _ => unreachable!(),
            })?;
            let public_key = load_file(match *name {
                "ES256" => "jwk/EC_P-256_public.jwk",
                "ES384" => "jwk/EC_P-384_public.jwk",
                "ES512" => "jwk/EC_P-521_public.jwk",
                "ES256K" => "jwk/EC_secp256k1_public.jwk",
                _ => unreachable!(),
            })?;

            let signer = alg.signer_from_jwk(&private_key)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_jwk(&public_key)?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_ecdsa_pkcs8_pem() -> Result<()> {
        let input = b"abcde12345";

        for name in &["ES256", "ES384", "ES512"] {
            let private_key = load_file(match *name {
                "ES256" => "pem/ecdsa_p256_pkcs8_private.pem",
                "ES384" => "pem/ecdsa_p384_pkcs8_private.pem",
                "ES512" => "pem/ecdsa_p521_pkcs8_private.pem",
                _ => unreachable!(),
            })?;
            let public_key = load_file(match *name {
                "ES256" => "pem/ecdsa_p256_pkcs8_public.pem",
                "ES384" => "pem/ecdsa_p384_pkcs8_public.pem",
                "ES512" => "pem/ecdsa_p521_pkcs8_public.pem",
                _ => unreachable!(),
            })?;

            let alg = EcdsaJwsAlgorithm::new(name);

            let signer = alg.signer_from_pem(&private_key)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_ecdsa_pkcs8_der() -> Result<()> {
        let input = b"abcde12345";

        for name in &["ES256", "ES384", "ES512"] {
            let private_key = load_file(match *name {
                "ES256" => "der/ecdsa_p256_pkcs8_private.der",
                "ES384" => "der/ecdsa_p384_pkcs8_private.der",
                "ES512" => "der/ecdsa_p521_pkcs8_private.der",
                _ => unreachable!(),
            })?;
            let public_key = load_file(match *name {
                "ES256" => "der/ecdsa_p256_pkcs8_public.der",
                "ES384" => "der/ecdsa_p384_pkcs8_public.der",
                "ES512" => "der/ecdsa_p521_pkcs8_public.der",
                _ => unreachable!(),
            })?;

            let alg = EcdsaJwsAlgorithm::new(name);

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

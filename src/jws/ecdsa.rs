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
pub enum EcdsaJwsAlgorithm {
    /// ECDSA using P-256 and SHA-256
    ES256,
    /// ECDSA using P-384 and SHA-384
    ES384,
    /// ECDSA using P-521 and SHA-512
    ES512,
    /// ECDSA using secp256k1 curve and SHA-256
    ES256K,
}

impl EcdsaJwsAlgorithm {
    /// Return a signer from a private key of EC JWK format.
    ///
    /// # Arguments
    /// * `input` - A private key of EC JWK format.
    pub fn signer_from_jwk(&self, input: impl AsRef<[u8]>) -> Result<EcdsaJwsSigner, JoseError> {
        (|| -> anyhow::Result<EcdsaJwsSigner> {
            let map: Map<String, Value> = serde_json::from_slice(input.as_ref())?;

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
                    builder.append_object_identifier(self.curve_oid());
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

    /// Return a signer from a private key of common or traditinal PEM format.
    ///
    /// Common PEM format is a DER and base64 encoded PKCS#8 PrivateKeyInfo
    /// that surrounded by "-----BEGIN/END PRIVATE KEY----".
    ///
    /// Traditional PEM format is a DER and base64 encoded ECPrivateKey
    /// that surrounded by "-----BEGIN/END EC PRIVATE KEY----".
    ///
    /// # Arguments
    /// * `input` - A private key of common or traditinal PEM format.
    pub fn signer_from_pem(&self, input: impl AsRef<[u8]>) -> Result<EcdsaJwsSigner, JoseError> {
        (|| -> anyhow::Result<EcdsaJwsSigner> {
            let (alg, data) = parse_pem(input.as_ref())?;
            let pkcs8;
            let pkcs8_ref = match alg.as_str() {
                "PRIVATE KEY" => {
                    if !self.detect_pkcs8(&data, false)? {
                        bail!("PEM contents is expected PKCS#8 wrapped key.");
                    }
                    &data
                }
                "EC PRIVATE KEY" => {
                    pkcs8 = self.to_pkcs8(&data, false);
                    &pkcs8
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };

            let pkey = PKey::private_key_from_der(pkcs8_ref)?;

            Ok(EcdsaJwsSigner {
                algorithm: &self,
                private_key: pkey,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a signer from a private key that is a DER encoded PKCS#8 PrivateKeyInfo or ECPrivateKey.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo or ECPrivateKey.
    pub fn signer_from_der(&self, input: impl AsRef<[u8]>) -> Result<EcdsaJwsSigner, JoseError> {
        (|| -> anyhow::Result<EcdsaJwsSigner> {
            let pkcs8;
            let pkcs8_ref = if self.detect_pkcs8(input.as_ref(), false)? {
                input.as_ref()
            } else {
                pkcs8 = self.to_pkcs8(input.as_ref(), false);
                &pkcs8
            };

            let pkey = PKey::private_key_from_der(pkcs8_ref)?;

            Ok(EcdsaJwsSigner {
                algorithm: &self,
                private_key: pkey,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a key of EC JWK format.
    ///
    /// # Arguments
    /// * `input` - A key of EC JWK format.
    pub fn verifier_from_jwk(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<EcdsaJwsVerifier, JoseError> {
        (|| -> anyhow::Result<EcdsaJwsVerifier> {
            let map: Map<String, Value> = serde_json::from_slice(input.as_ref())?;

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

    /// Return a verifier from a key of common or traditional PEM format.
    ///
    /// Common PEM format is a DER and base64 encoded SubjectPublicKeyInfo
    /// that surrounded by "-----BEGIN/END PUBLIC KEY----".
    ///
    /// Traditional PEM format is a DER and base64 ECParameters
    /// that surrounded by "-----BEGIN/END EC PUBLIC KEY----".
    ///
    /// # Arguments
    /// * `input` - A public key of common or traditional PEM format.
    pub fn verifier_from_pem(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<EcdsaJwsVerifier, JoseError> {
        (|| -> anyhow::Result<EcdsaJwsVerifier> {
            let (alg, data) = parse_pem(input.as_ref())?;

            let pkcs8;
            let pkcs8_ref = match alg.as_str() {
                "PUBLIC KEY" => {
                    if !self.detect_pkcs8(&data, true)? {
                        bail!("PEM contents is expected PKCS#8 wrapped key.");
                    }
                    &data
                }
                "EC PUBLIC KEY" => {
                    pkcs8 = self.to_pkcs8(&data, true);
                    &pkcs8
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };

            let pkey = PKey::public_key_from_der(pkcs8_ref)?;

            Ok(EcdsaJwsVerifier {
                algorithm: &self,
                public_key: pkey,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a public key that is a DER encoded SubjectPublicKeyInfo or ECPoint.
    ///
    /// # Arguments
    /// * `input` - A public key that is a DER encoded SubjectPublicKeyInfo or ECPoint.
    pub fn verifier_from_der(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<EcdsaJwsVerifier, JoseError> {
        (|| -> anyhow::Result<EcdsaJwsVerifier> {
            let pkcs8;
            let pkcs8_ref = if self.detect_pkcs8(input.as_ref(), true)? {
                input.as_ref()
            } else {
                pkcs8 = self.to_pkcs8(input.as_ref(), true);
                &pkcs8
            };

            let pkey = PKey::public_key_from_der(pkcs8_ref)?;

            Ok(EcdsaJwsVerifier {
                algorithm: &self,
                public_key: pkey,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn curve_name(&self) -> &str {
        match self {
            Self::ES256 => "P-256",
            Self::ES384 => "P-384",
            Self::ES512 => "P-521",
            Self::ES256K => "secp256k1",
        }
    }

    fn curve_oid(&self) -> &ObjectIdentifier {
        match self {
            Self::ES256 => &*OID_PRIME256V1,
            Self::ES384 => &*OID_SECP384R1,
            Self::ES512 => &*OID_SECP521R1,
            Self::ES256K => &*OID_SECP256K1,
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
                            if &val != self.curve_oid() {
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
                builder.append_object_identifier(self.curve_oid());
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

impl JwsAlgorithm for EcdsaJwsAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
            Self::ES512 => "ES512",
            Self::ES256K => "ES256K",
        }
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

    fn sign(&self, message: &mut dyn Read) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let message_digest = match self.algorithm {
                EcdsaJwsAlgorithm::ES256 => MessageDigest::sha256(),
                EcdsaJwsAlgorithm::ES384 => MessageDigest::sha384(),
                EcdsaJwsAlgorithm::ES512 => MessageDigest::sha512(),
                EcdsaJwsAlgorithm::ES256K => MessageDigest::sha256(),
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

pub struct EcdsaJwsVerifier<'a> {
    algorithm: &'a EcdsaJwsAlgorithm,
    public_key: PKey<Public>,
}

impl<'a> JwsVerifier<EcdsaJwsAlgorithm> for EcdsaJwsVerifier<'a> {
    fn algorithm(&self) -> &EcdsaJwsAlgorithm {
        &self.algorithm
    }

    fn verify(&self, message: &mut dyn Read, signature: &[u8]) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            let message_digest = match self.algorithm {
                EcdsaJwsAlgorithm::ES256 => MessageDigest::sha256(),
                EcdsaJwsAlgorithm::ES384 => MessageDigest::sha384(),
                EcdsaJwsAlgorithm::ES512 => MessageDigest::sha512(),
                EcdsaJwsAlgorithm::ES256K => MessageDigest::sha256(),
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
    fn sign_and_verify_ecdsa_jwt() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            EcdsaJwsAlgorithm::ES256,
            EcdsaJwsAlgorithm::ES384,
            EcdsaJwsAlgorithm::ES512,
            EcdsaJwsAlgorithm::ES256K,
        ] {
            let private_key = load_file(match alg {
                EcdsaJwsAlgorithm::ES256 => "jwk/EC_P-256_private.jwk",
                EcdsaJwsAlgorithm::ES384 => "jwk/EC_P-384_private.jwk",
                EcdsaJwsAlgorithm::ES512 => "jwk/EC_P-521_private.jwk",
                EcdsaJwsAlgorithm::ES256K => "jwk/EC_secp256k1_private.jwk",
            })?;
            let public_key = load_file(match alg {
                EcdsaJwsAlgorithm::ES256 => "jwk/EC_P-256_public.jwk",
                EcdsaJwsAlgorithm::ES384 => "jwk/EC_P-384_public.jwk",
                EcdsaJwsAlgorithm::ES512 => "jwk/EC_P-521_public.jwk",
                EcdsaJwsAlgorithm::ES256K => "jwk/EC_secp256k1_public.jwk",
            })?;

            let signer = alg.signer_from_jwk(&private_key)?;
            let signature = signer.sign(&mut Cursor::new(input))?;

            let verifier = alg.verifier_from_jwk(&public_key)?;
            verifier.verify(&mut Cursor::new(input), &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_ecdsa_pkcs8_pem() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            EcdsaJwsAlgorithm::ES256,
            EcdsaJwsAlgorithm::ES384,
            EcdsaJwsAlgorithm::ES512,
            EcdsaJwsAlgorithm::ES256K,
        ] {
            let private_key = load_file(match alg {
                EcdsaJwsAlgorithm::ES256 => "pem/ECDSA_P-256_pkcs8_private.pem",
                EcdsaJwsAlgorithm::ES384 => "pem/ECDSA_P-384_pkcs8_private.pem",
                EcdsaJwsAlgorithm::ES512 => "pem/ECDSA_P-521_pkcs8_private.pem",
                EcdsaJwsAlgorithm::ES256K => "pem/ECDSA_secp256k1_pkcs8_private.pem",
            })?;
            let public_key = load_file(match alg {
                EcdsaJwsAlgorithm::ES256 => "pem/ECDSA_P-256_pkcs8_public.pem",
                EcdsaJwsAlgorithm::ES384 => "pem/ECDSA_P-384_pkcs8_public.pem",
                EcdsaJwsAlgorithm::ES512 => "pem/ECDSA_P-521_pkcs8_public.pem",
                EcdsaJwsAlgorithm::ES256K => "pem/ECDSA_secp256k1_pkcs8_public.pem",
            })?;

            let signer = alg.signer_from_pem(&private_key)?;
            let signature = signer.sign(&mut Cursor::new(input))?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            verifier.verify(&mut Cursor::new(input), &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_ecdsa_pkcs8_der() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            EcdsaJwsAlgorithm::ES256,
            EcdsaJwsAlgorithm::ES384,
            EcdsaJwsAlgorithm::ES512,
            EcdsaJwsAlgorithm::ES256K,
        ] {
            let private_key = load_file(match alg {
                EcdsaJwsAlgorithm::ES256 => "der/ECDSA_P-256_pkcs8_private.der",
                EcdsaJwsAlgorithm::ES384 => "der/ECDSA_P-384_pkcs8_private.der",
                EcdsaJwsAlgorithm::ES512 => "der/ECDSA_P-521_pkcs8_private.der",
                EcdsaJwsAlgorithm::ES256K => "der/ECDSA_secp256k1_pkcs8_private.der",
            })?;
            let public_key = load_file(match alg {
                EcdsaJwsAlgorithm::ES256 => "der/ECDSA_P-256_pkcs8_public.der",
                EcdsaJwsAlgorithm::ES384 => "der/ECDSA_P-384_pkcs8_public.der",
                EcdsaJwsAlgorithm::ES512 => "der/ECDSA_P-521_pkcs8_public.der",
                EcdsaJwsAlgorithm::ES256K => "der/ECDSA_secp256k1_pkcs8_public.der",
            })?;

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

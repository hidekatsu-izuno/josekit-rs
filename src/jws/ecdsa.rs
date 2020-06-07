use anyhow::{anyhow, bail};
use openssl::ec::{EcKey, EcGroup};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{HasPublic, PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use openssl::bn::BigNum;
use serde_json::{Map, Value};

use crate::jws::{JwsAlgorithm, JwsSigner, JwsVerifier};
use crate::jws::util::{json_eq, json_base64_bytes};
use crate::error::JoseError;

/// ECDSA using P-256 and SHA-256
pub const ES256: EcdsaJwsAlgorithm = EcdsaJwsAlgorithm::new("ES256");

/// ECDSA using P-384 and SHA-384
pub const ES384: EcdsaJwsAlgorithm = EcdsaJwsAlgorithm::new("ES384");

/// ECDSA using P-521 and SHA-512
pub const ES512: EcdsaJwsAlgorithm = EcdsaJwsAlgorithm::new("ES512");

// ECDSA using secp256k1 curve and SHA-256
pub const ES256K: EcdsaJwsAlgorithm = EcdsaJwsAlgorithm::new("ES256K");

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
        EcdsaJwsAlgorithm {
            name,
        }
    }

    /// Return a signer from a private key of JWK format.
    ///
    /// # Arguments
    /// * `data` - A private key of JWK format.
    pub fn signer_from_jwk<'a>(
        &'a self,
        data: &[u8],
    ) -> Result<impl JwsSigner<EcdsaJwsAlgorithm> + 'a, JoseError> {
        (|| -> anyhow::Result<EcdsaJwsSigner> {
            let map: Map<String, Value> = serde_json::from_slice(data)?;

            json_eq(&map, "alg", &self.name())?;
            json_eq(&map, "kty", "EC")?;
            json_eq(&map, "use", "sig")?;
            let d = json_base64_bytes(&map, "d")?;
            let x = json_base64_bytes(&map, "x")?;
            let y = json_base64_bytes(&map, "y")?;

            let crv = Self::curve(&map, "crv")?;
            let ec_group = EcGroup::from_curve_name(crv)?;
            let public_key = EcKey::from_public_key_affine_coordinates(
                ec_group.as_ref(),
                BigNum::from_slice(&x)?.as_ref(),
                BigNum::from_slice(&y)?.as_ref()
            )?;

            let pkey = EcKey::from_private_components(
                ec_group.as_ref(),
                BigNum::from_slice(&d)?.as_ref(),
                public_key.public_key()
            ).and_then(|val| PKey::from_ec_key(val))?;

            self.check_key(&pkey)?;

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
    /// * `data` - A private key of PKCS#1 or PKCS#8 PEM format.
    pub fn signer_from_pem<'a>(
        &'a self,
        data: &[u8],
    ) -> Result<impl JwsSigner<Self> + 'a, JoseError> {
        (|| -> anyhow::Result<EcdsaJwsSigner> {
            let pkey = PKey::private_key_from_pem(&data)
                .or_else(|err| {
                    EcKey::private_key_from_pem(&data)
                        .and_then(|val| PKey::from_ec_key(val))
                        .map_err(|_| err)
                })?;
            
            self.check_key(&pkey)?;

            Ok(EcdsaJwsSigner {
                algorithm: &self,
                private_key: pkey,
            })
        })().map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a signer from a private key of PKCS#1 or PKCS#8 DER format.
    ///
    /// # Arguments
    /// * `data` - A private key of PKCS#1 or PKCS#8 DER format.
    pub fn signer_from_der<'a>(
        &'a self,
        data: &[u8],
    ) -> Result<impl JwsSigner<Self> + 'a, JoseError> {
        (|| -> anyhow::Result<EcdsaJwsSigner> {
            let pkey = PKey::private_key_from_der(&data)
                .or_else(|err| {
                    EcKey::private_key_from_der(&data)
                        .and_then(|val| PKey::from_ec_key(val))
                        .map_err(|_| err)
                })?;
            
            self.check_key(&pkey)?;

            Ok(EcdsaJwsSigner {
                algorithm: &self,
                private_key: pkey,
            })
        })().map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a key of JWK format.
    ///
    /// # Arguments
    /// * `data` - A key of JWK format.
    pub fn verifier_from_jwk<'a>(
        &'a self,
        data: &[u8],
    ) -> Result<impl JwsVerifier<Self> + 'a, JoseError> {
        (|| -> anyhow::Result<EcdsaJwsVerifier> {
            let map: Map<String, Value> = serde_json::from_slice(data)
                .map_err(|err| anyhow!(err))?;

            json_eq(&map, "alg", &self.name())?;
            json_eq(&map, "kty", "EC")?;
            json_eq(&map, "use", "sig")?;
            let x = json_base64_bytes(&map, "x")?;
            let y = json_base64_bytes(&map, "y")?;

            let crv = Self::curve(&map, "crv")?;
            let ec_group = EcGroup::from_curve_name(crv)?;

            let pkey = EcKey::from_public_key_affine_coordinates(
                ec_group.as_ref(),
                BigNum::from_slice(&x)?.as_ref(),
                BigNum::from_slice(&y)?.as_ref()
            ).and_then(|val| PKey::from_ec_key(val))?;

            self.check_key(&pkey)?;

            Ok(EcdsaJwsVerifier {
                algorithm: &self,
                public_key: pkey,
            })
        })().map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a key of PKCS#8 PEM format.
    ///
    /// # Arguments
    /// * `data` - A key of PKCS#8 PEM format.
    pub fn verifier_from_pem<'a>(
        &'a self,
        data: &[u8],
    ) -> Result<impl JwsVerifier<Self> + 'a, JoseError> {
        (|| -> anyhow::Result<EcdsaJwsVerifier> {
            let pkey = PKey::public_key_from_pem(&data)?;

            self.check_key(&pkey)?;

            Ok(EcdsaJwsVerifier {
                algorithm: &self,
                public_key: pkey,
            })
        })().map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a key of PKCS#8 DER format.
    ///
    /// # Arguments
    /// * `data` - A key of PKCS#8 DER format.
    pub fn verifier_from_der<'a>(
        &'a self,
        data: &[u8],
    ) -> Result<impl JwsVerifier<Self> + 'a, JoseError> {
        (|| -> anyhow::Result<EcdsaJwsVerifier> {
            let pkey = PKey::public_key_from_der(&data)?;

            self.check_key(&pkey)?;

            Ok(EcdsaJwsVerifier {
                algorithm: &self,
                public_key: pkey,
            })
        })().map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn check_key<T: HasPublic>(&self, pkey: &PKey<T>) -> anyhow::Result<()> {
        let ec_key = pkey.ec_key()?;

        let curve_name = match self.name {
            "ES256" => Nid::X9_62_PRIME256V1,
            "ES384" => Nid::SECP384R1,
            "ES512" => Nid::SECP521R1,
            "ES256K" => Nid::SECP256K1,
            _ => unimplemented!()
        };

        match ec_key.group().curve_name() {
            Some(val) if val == curve_name => {}
            _ => bail!("Inappropriate curve: {:?}", curve_name),
        }

        Ok(())
    }

    fn curve(map: &Map<String, Value>, key: &str) -> anyhow::Result<Nid> {
        if let Some(Value::String(val)) = map.get(key) {
            match val.as_str() {
                "P-256" => Ok(Nid::X9_62_PRIME256V1),
                "P-384" => Ok(Nid::SECP384R1),
                "P-521" => Ok(Nid::SECP521R1),
                "secp256k1" => Ok(Nid::SECP256K1),
                _ => bail!("Unsupported curve: {}", val)
            }
        } else {
            bail!("Key crv is missing.");
        }
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

    fn sign(&self, data: &[&[u8]]) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let message_digest = match self.algorithm.name {
                "ES256" | "ES256K" => MessageDigest::sha256(),
                "ES384" => MessageDigest::sha384(),
                "ES512" => MessageDigest::sha512(),
                _ => unreachable!(),
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

pub struct EcdsaJwsVerifier<'a> {
    algorithm: &'a EcdsaJwsAlgorithm,
    public_key: PKey<Public>,
}

impl<'a> JwsVerifier<EcdsaJwsAlgorithm> for EcdsaJwsVerifier<'a> {
    fn algorithm(&self) -> &EcdsaJwsAlgorithm {
        &self.algorithm
    }

    fn verify(&self, data: &[&[u8]], signature: &[u8]) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            let message_digest = match self.algorithm.name {
                "ES256" | "ES256K" => MessageDigest::sha256(),
                "ES384" => MessageDigest::sha384(),
                "ES512" => MessageDigest::sha512(),
                _ => unreachable!(),
            };

            let mut verifier = Verifier::new(message_digest, &self.public_key)?;
            for part in data {
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
    fn sign_and_verify_jwt() -> Result<()> {
        let data = b"abcde12345";

        for name in &[
            "ES256",
            "ES384",
            "ES512",
         ] {
            let alg = EcdsaJwsAlgorithm::new(name);

            let private_key = load_file(match *name {
                "ES256" => "jwk/es256_private.jwk",
                "ES384" => "jwk/es384_private.jwk",
                "ES512" => "jwk/es512_private.jwk",
                _ => unreachable!()
            })?;
            let public_key = load_file(match *name {
                "ES256" => "jwk/es256_public.jwk",
                "ES384" => "jwk/es384_public.jwk",
                "ES512" => "jwk/es512_public.jwk",
                _ => unreachable!()
            })?;

            let signer = alg.signer_from_jwk(&private_key)?;
            let signature = signer.sign(&[data])?;

            let verifier = alg.verifier_from_jwk(&public_key)?;
            verifier.verify(&[data], &signature)?;
        }

        Ok(())
    }
    
    #[test]
    fn sign_and_verify_pkcs8_pem() -> Result<()> {
        let data = b"abcde12345";

        for name in &[
            "ES256",
            "ES384",
            "ES512",
        ] {
            let private_key = load_file(match *name {
                "ES256" => "pem/ecdsa_p256_pkcs8_private.pem",
                "ES384" => "pem/ecdsa_p384_pkcs8_private.pem",
                "ES512" => "pem/ecdsa_p521_pkcs8_private.pem",
                _ => unreachable!()
            })?;
            let public_key = load_file(match *name {
                "ES256" => "pem/ecdsa_p256_pkcs8_public.pem",
                "ES384" => "pem/ecdsa_p384_pkcs8_public.pem",
                "ES512" => "pem/ecdsa_p521_pkcs8_public.pem",
                _ => unreachable!()
            })?;

            let alg = EcdsaJwsAlgorithm::new(name);

            let signer = alg.signer_from_pem(&private_key)?;
            let signature = signer.sign(&[data])?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            verifier.verify(&[data], &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_pkcs8_der() -> Result<()> {
        let data = b"abcde12345";

        for name in &[
            "ES256",
            "ES384",
            "ES512",
        ] {
            let private_key = load_file(match *name {
                "ES256" => "der/ecdsa_p256_pkcs8_private.der",
                "ES384" => "der/ecdsa_p384_pkcs8_private.der",
                "ES512" => "der/ecdsa_p521_pkcs8_private.der",
                _ => unreachable!()
            })?;
            let public_key = load_file(match *name {
                "ES256" => "der/ecdsa_p256_pkcs8_public.der",
                "ES384" => "der/ecdsa_p384_pkcs8_public.der",
                "ES512" => "der/ecdsa_p521_pkcs8_public.der",
                _ => unreachable!()
            })?;

            let alg = EcdsaJwsAlgorithm::new(name);

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

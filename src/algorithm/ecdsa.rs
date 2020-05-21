use anyhow::{anyhow, bail};
use openssl::ec::{EcKey, EcGroup};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{HasPublic, PKey, Private, Public};
use serde_json::{Map, Value};

use crate::algorithm::{Algorithm, HashAlgorithm, Signer, Verifier};
use crate::algorithm::openssl::{json_eq, json_base64_num};
use crate::error::JwtError;

#[derive(Debug, Eq, PartialEq)]
pub struct EcdsaAlgorithm {
    name: &'static str,
    hash_algorithm: HashAlgorithm,
}

impl EcdsaAlgorithm {
    /// Return a new instance.
    ///
    /// # Arguments
    /// * `name` - A algrithm name.
    /// * `hash_algorithm` - A algrithm name.
    pub const fn new(name: &'static str, hash_algorithm: HashAlgorithm) -> Self {
        EcdsaAlgorithm {
            name,
            hash_algorithm
        }
    }

    /// Return a signer from a private key of JWK format.
    ///
    /// # Arguments
    /// * `data` - A private key of JWK format.
    pub fn signer_from_jwk<'a>(
        &'a self,
        data: &[u8],
    ) -> Result<impl Signer<EcdsaAlgorithm> + 'a, JwtError> {
        (|| -> anyhow::Result<EcdsaSigner> {
            let map: Map<String, Value> = serde_json::from_slice(data)
                .map_err(|err| anyhow!(err))?;

            json_eq(&map, "alg", &self.name())?;
            json_eq(&map, "kty", "EC")?;
            json_eq(&map, "use", "sig")?;

            let crv = Self::curve(&map, "crv")?;
            let ec_group = EcGroup::from_curve_name(crv)?;
            let private_number = json_base64_num(&map, "d")?;
            let x = json_base64_num(&map, "x")?;
            let y = json_base64_num(&map, "y")?;
            let public_key = EcKey::from_public_key_affine_coordinates(
                ec_group.as_ref(),
                x.as_ref(),
                y.as_ref()
            )?;

            EcKey::from_private_components(
                ec_group.as_ref(),
                private_number.as_ref(),
                public_key.public_key()
            )
                .and_then(|val| PKey::from_ec_key(val))
                .map_err(|err| anyhow!(err))
                .map(|val| EcdsaSigner {
                    algorithm: &self,
                    private_key: val,
                })
        })()
        .map_err(|err| JwtError::InvalidKeyFormat(err))
    }

    /// Return a signer from a private key of PKCS#1 or PKCS#8 PEM format.
    ///
    /// # Arguments
    /// * `data` - A private key of PKCS#1 or PKCS#8 PEM format.
    pub fn signer_from_pem<'a>(
        &'a self,
        data: &[u8],
    ) -> Result<impl Signer<EcdsaAlgorithm> + 'a, JwtError> {
        PKey::private_key_from_pem(&data)
            .or_else(|err| {
                EcKey::private_key_from_pem(&data)
                    .and_then(|val| PKey::from_ec_key(val))
                    .map_err(|_| anyhow!(err))
            })
            .and_then(|pkey| (&self).check_key(pkey))
            .map_err(|err| JwtError::InvalidKeyFormat(err))
            .map(|val| EcdsaSigner {
                algorithm: &self,
                private_key: val,
            })
    }

    /// Return a signer from a private key of PKCS#1 or PKCS#8 DER format.
    ///
    /// # Arguments
    /// * `data` - A private key of PKCS#1 or PKCS#8 DER format.
    pub fn signer_from_der<'a>(
        &'a self,
        data: &[u8],
    ) -> Result<impl Signer<EcdsaAlgorithm> + 'a, JwtError> {
        PKey::private_key_from_der(&data)
            .or_else(|err| {
                EcKey::private_key_from_der(&data)
                    .and_then(|val| PKey::from_ec_key(val))
                    .map_err(|_| anyhow!(err))
            })
            .and_then(|pkey| (&self).check_key(pkey))
            .map_err(|err| JwtError::InvalidKeyFormat(err))
            .map(|val| EcdsaSigner {
                algorithm: &self,
                private_key: val,
            })
    }

    /// Return a verifier from a key of JWK format.
    ///
    /// # Arguments
    /// * `data` - A key of JWK format.
    pub fn verifier_from_jwk<'a>(
        &'a self,
        data: &[u8],
    ) -> Result<impl Verifier<EcdsaAlgorithm> + 'a, JwtError> {
        (|| -> anyhow::Result<EcdsaVerifier> {
            let map: Map<String, Value> = serde_json::from_slice(data)
                .map_err(|err| anyhow!(err))?;

            json_eq(&map, "alg", &self.name())?;
            json_eq(&map, "kty", "EC")?;
            json_eq(&map, "use", "sig")?;

            let crv = Self::curve(&map, "crv")?;
            let ec_group = EcGroup::from_curve_name(crv)?;
            let x = json_base64_num(&map, "x")?;
            let y = json_base64_num(&map, "y")?;

            EcKey::from_public_key_affine_coordinates(
                ec_group.as_ref(),
                x.as_ref(),
                y.as_ref()
            )
                .and_then(|val| PKey::from_ec_key(val))
                .map_err(|err| anyhow!(err))
                .map(|val| EcdsaVerifier {
                    algorithm: &self,
                    public_key: val,
                })
        })()
        .map_err(|err| JwtError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a key of PKCS#8 PEM format.
    ///
    /// # Arguments
    /// * `data` - A key of PKCS#8 PEM format.
    pub fn verifier_from_pem<'a>(
        &'a self,
        data: &[u8],
    ) -> Result<impl Verifier<EcdsaAlgorithm> + 'a, JwtError> {
        PKey::public_key_from_pem(&data)
            .map_err(|err| anyhow!(err))
            .and_then(|pkey| (&self).check_key(pkey))
            .map_err(|err| JwtError::InvalidKeyFormat(err))
            .map(|val| EcdsaVerifier {
                algorithm: &self,
                public_key: val,
            })
    }

    /// Return a verifier from a key of PKCS#8 DER format.
    ///
    /// # Arguments
    /// * `data` - A key of PKCS#8 DER format.
    pub fn verifier_from_der<'a>(
        &'a self,
        data: &[u8],
    ) -> Result<impl Verifier<EcdsaAlgorithm> + 'a, JwtError> {
        PKey::public_key_from_der(&data)
            .map_err(|err| anyhow!(err))
            .and_then(|pkey| (&self).check_key(pkey))
            .map_err(|err| JwtError::InvalidKeyFormat(err))
            .map(|val| EcdsaVerifier {
                algorithm: &self,
                public_key: val,
            })
    }

    fn check_key<T>(&self, pkey: PKey<T>) -> anyhow::Result<PKey<T>>
    where
        T: HasPublic,
    {
        let ec_key = pkey.ec_key()?;

        let curve_name = match self.hash_algorithm {
            HashAlgorithm::SHA256 => Nid::X9_62_PRIME256V1,
            HashAlgorithm::SHA384 => Nid::SECP384R1,
            HashAlgorithm::SHA512 => Nid::SECP521R1,
        };

        match ec_key.group().curve_name() {
            Some(val) if val == curve_name => {}
            _ => bail!("Inappropriate curve: {:?}", curve_name),
        }

        Ok(pkey)
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

impl Algorithm for EcdsaAlgorithm {
    fn name(&self) -> &str {
        self.name
    }
}

pub struct EcdsaSigner<'a> {
    algorithm: &'a EcdsaAlgorithm,
    private_key: PKey<Private>,
}

impl<'a> Signer<EcdsaAlgorithm> for EcdsaSigner<'a> {
    fn algorithm(&self) -> &EcdsaAlgorithm {
        &self.algorithm
    }

    fn sign(&self, data: &[&[u8]]) -> Result<Vec<u8>, JwtError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let message_digest = match self.algorithm.hash_algorithm {
                HashAlgorithm::SHA256 => MessageDigest::sha256(),
                HashAlgorithm::SHA384 => MessageDigest::sha384(),
                HashAlgorithm::SHA512 => MessageDigest::sha512(),
            };

            let mut signer = openssl::sign::Signer::new(message_digest, &self.private_key)?;
            for part in data {
                signer.update(part)?;
            }
            let signature = signer.sign_to_vec()?;
            Ok(signature)
        })()
        .map_err(|err| JwtError::InvalidSignature(err))
    }
}

pub struct EcdsaVerifier<'a> {
    algorithm: &'a EcdsaAlgorithm,
    public_key: PKey<Public>,
}

impl<'a> Verifier<EcdsaAlgorithm> for EcdsaVerifier<'a> {
    fn algorithm(&self) -> &EcdsaAlgorithm {
        &self.algorithm
    }

    fn verify(&self, data: &[&[u8]], signature: &[u8]) -> Result<(), JwtError> {
        (|| -> anyhow::Result<()> {
            let message_digest = match self.algorithm.hash_algorithm {
                HashAlgorithm::SHA256 => MessageDigest::sha256(),
                HashAlgorithm::SHA384 => MessageDigest::sha384(),
                HashAlgorithm::SHA512 => MessageDigest::sha512(),
            };

            let mut verifier = openssl::sign::Verifier::new(message_digest, &self.public_key)?;
            for part in data {
                verifier.update(part)?;
            }
            verifier.verify(signature)?;
            Ok(())
        })()
        .map_err(|err| JwtError::InvalidSignature(err))
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
            let alg = EcdsaAlgorithm::new(name, hash_algorithm(name));

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

            let alg = EcdsaAlgorithm::new(name, hash_algorithm(name));

            let signer = alg.signer_from_der(&private_key)?;
            let signature = signer.sign(&[data])?;

            let verifier = alg.verifier_from_der(&public_key)?;
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

            let alg = EcdsaAlgorithm::new(name, hash_algorithm(name));

            let signer = alg.signer_from_der(&private_key)?;
            let signature = signer.sign(&[data])?;

            let verifier = alg.verifier_from_der(&public_key)?;
            verifier.verify(&[data], &signature)?;
        }

        Ok(())
    }

    fn hash_algorithm(name: &str) -> HashAlgorithm {
        match name {
            "ES256" => HashAlgorithm::SHA256,
            "ES384" => HashAlgorithm::SHA384,
            "ES512" => HashAlgorithm::SHA512,
            _ => unreachable!()
        }
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

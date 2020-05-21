use anyhow::{anyhow, bail};
use openssl::hash::MessageDigest;
use openssl::pkey::{HasPublic, PKey, Private, Public};
use openssl::rsa::Rsa;
use serde_json::{Map, Value};

use crate::algorithm::{Algorithm, HashAlgorithm, Signer, Verifier};
use crate::algorithm::openssl::{json_eq, json_base64_num};
use crate::error::JwtError;

#[derive(Debug, Eq, PartialEq)]
pub struct RsaAlgorithm {
    name: &'static str,
    hash_algorithm: HashAlgorithm,
}

impl RsaAlgorithm {
    /// Return a new instance.
    ///
    /// # Arguments
    /// * `name` - A algrithm name.
    /// * `hash_algorithm` - A algrithm name.
    pub const fn new(name: &'static str, hash_algorithm: HashAlgorithm) -> Self {
        RsaAlgorithm {
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
    ) -> Result<impl Signer<RsaAlgorithm> + 'a, JwtError> {
        (|| -> anyhow::Result<RsaSigner> {
            let map: Map<String, Value> = serde_json::from_slice(data)
                .map_err(|err| anyhow!(err))?;

            json_eq(&map, "alg", &self.name())?;
            json_eq(&map, "kty", "RSA")?;
            json_eq(&map, "use", "sig")?;

            Rsa::from_private_components(
                json_base64_num(&map, "n")?,
                json_base64_num(&map, "e")?,
                json_base64_num(&map, "d")?,
                json_base64_num(&map, "p")?,
                json_base64_num(&map, "q")?,
                json_base64_num(&map, "dp")?,
                json_base64_num(&map, "dq")?,
                json_base64_num(&map, "iq")?
            )
                .and_then(|val| PKey::from_rsa(val))
                .map_err(|err| anyhow!(err))
                .map(|val| RsaSigner {
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
    ) -> Result<impl Signer<RsaAlgorithm> + 'a, JwtError> {
        PKey::private_key_from_pem(&data)
            .or_else(|err| {
                Rsa::private_key_from_pem(&data)
                    .and_then(|val| PKey::from_rsa(val))
                    .map_err(|_| anyhow!(err))
            })
            .and_then(|pkey| (&self).check_key(pkey))
            .map_err(|err| JwtError::InvalidKeyFormat(err))
            .map(|val| RsaSigner {
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
    ) -> Result<impl Signer<RsaAlgorithm> + 'a, JwtError> {
        PKey::private_key_from_der(&data)
            .or_else(|err| {
                Rsa::private_key_from_der(&data)
                    .and_then(|val| PKey::from_rsa(val))
                    .map_err(|_| anyhow!(err))
            })
            .and_then(|pkey| (&self).check_key(pkey))
            .map_err(|err| JwtError::InvalidKeyFormat(err))
            .map(|val| RsaSigner {
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
    ) -> Result<impl Verifier<RsaAlgorithm> + 'a, JwtError> {
        (|| -> anyhow::Result<RsaVerifier> {
            let map: Map<String, Value> = serde_json::from_slice(data)
                .map_err(|err| anyhow!(err))?;

            json_eq(&map, "alg", &self.name())?;
            json_eq(&map, "kty", "RSA")?;
            json_eq(&map, "use", "sig")?;

            Rsa::from_public_components(
                json_base64_num(&map, "n")?,
                json_base64_num(&map, "e")?
            )
                .and_then(|val| PKey::from_rsa(val))
                .map_err(|err| anyhow!(err))
                .map(|val| RsaVerifier {
                    algorithm: &self,
                    public_key: val,
                })
        })()
        .map_err(|err| JwtError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a public key of PKCS#1 or PKCS#8 PEM format.
    ///
    /// # Arguments
    /// * `data` - A public key of PKCS#1 or PKCS#8 PEM format.
    pub fn verifier_from_pem<'a>(
        &'a self,
        data: &[u8],
    ) -> Result<impl Verifier<RsaAlgorithm> + 'a, JwtError> {
        PKey::public_key_from_pem(&data)
            .or_else(|err| {
                Rsa::public_key_from_pem_pkcs1(&data)
                    .and_then(|val| PKey::from_rsa(val))
                    .map_err(|_| anyhow!(err))
            })
            .and_then(|pkey| (&self).check_key(pkey))
            .map_err(|err| JwtError::InvalidKeyFormat(err))
            .map(|val| RsaVerifier {
                algorithm: &self,
                public_key: val,
            })
    }

    /// Return a verifier from a public key of PKCS#1 or PKCS#8 DER format.
    ///
    /// # Arguments
    /// * `data` - A public key of PKCS#1 or PKCS#8 DER format.
    pub fn verifier_from_der<'a>(
        &'a self,
        data: &[u8],
    ) -> Result<impl Verifier<RsaAlgorithm> + 'a, JwtError> {
        PKey::public_key_from_der(&data)
            .or_else(|err| {
                Rsa::public_key_from_der_pkcs1(&data)
                    .and_then(|val| PKey::from_rsa(val))
                    .map_err(|_| anyhow!(err))
            })
            .and_then(|pkey| (&self).check_key(pkey))
            .map_err(|err| JwtError::InvalidKeyFormat(err))
            .map(|val| RsaVerifier {
                algorithm: &self,
                public_key: val,
            })
    }

    fn check_key<T>(&self, pkey: PKey<T>) -> anyhow::Result<PKey<T>>
    where
        T: HasPublic,
    {
        let rsa = pkey.rsa()?;

        if rsa.size() * 8 < 2048 {
            bail!("key length must be 2048 or more.");
        }

        Ok(pkey)
    }
}

impl Algorithm for RsaAlgorithm {
    fn name(&self) -> &str {
        self.name
    }
}

pub struct RsaSigner<'a> {
    algorithm: &'a RsaAlgorithm,
    private_key: PKey<Private>,
}

impl<'a> Signer<RsaAlgorithm> for RsaSigner<'a> {
    fn algorithm(&self) -> &RsaAlgorithm {
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

pub struct RsaVerifier<'a> {
    algorithm: &'a RsaAlgorithm,
    public_key: PKey<Public>,
}

impl<'a> Verifier<RsaAlgorithm> for RsaVerifier<'a> {
    fn algorithm(&self) -> &RsaAlgorithm {
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
    fn load_private_pem() -> Result<()> {
        for name in &[
            "RS256",
            "PS256",
            "PS384",
            "PS512",
         ] {
            let private_key = load_file(match *name {
                "PS256" => "keys/rsapss_2048_sha256_private.pem",
                "PS384" => "keys/rsapss_2048_sha384_private.pem",
                "PS512" => "keys/rsapss_2048_sha512_private.pem",
                _ => "keys/rsa_2048_private.pem"
            })?;
            let alg = RsaAlgorithm::new(name, hash_algorithm(name));
            let _ = alg.signer_from_pem(&private_key)?;
        }
        Ok(())
    }

    #[test]
    fn load_private_der() -> Result<()> {
        for name in &[
            "RS256",
            "PS256",
            "PS384",
            "PS512",
         ] {
            let private_key = load_file(match *name {
                "PS256" => "keys/rsapss_2048_sha256_private.der",
                "PS384" => "keys/rsapss_2048_sha384_private.der",
                "PS512" => "keys/rsapss_2048_sha512_private.der",
                _ => "keys/rsa_2048_private.der"
            })?;
            let alg = RsaAlgorithm::new(name, hash_algorithm(name));
            let _ = alg.signer_from_der(&private_key)?;
        }
        Ok(())
    }

    #[test]
    fn load_private_pk1_pem() -> Result<()> {
        for name in &[
            "RS256"
         ] {
            let private_key = load_file(match *name {
                _ => "keys/rsa_2048_pk1_private.pem"
            })?;
            let alg = RsaAlgorithm::new(name, hash_algorithm(name));
            let _ = alg.signer_from_pem(&private_key)?;
        }
        Ok(())
    }

    #[test]
    fn load_private_pk1_der() -> Result<()> {
        for name in &[
            "RS256"
         ] {
            let private_key = load_file(match *name {
                _ => "keys/rsa_2048_pk1_private.der"
            })?;
            let alg = RsaAlgorithm::new(name, hash_algorithm(name));
            let _ = alg.signer_from_der(&private_key)?;
        }
        Ok(())
    }

    #[test]
    fn load_public_pem() -> Result<()> {
        for name in &[
            "RS256",
            "PS256",
            "PS384",
            "PS512",
         ] {
            let public_key = load_file(match *name {
                "PS256" => "keys/rsapss_2048_sha256_public.pem",
                "PS384" => "keys/rsapss_2048_sha384_public.pem",
                "PS512" => "keys/rsapss_2048_sha512_public.pem",
                _ => "keys/rsa_2048_public.pem"
            })?;
            let alg = RsaAlgorithm::new(name, hash_algorithm(name));
            let _ = alg.verifier_from_pem(&public_key)?;
        }
        Ok(())
    }

    #[test]
    fn load_public_der() -> Result<()> {
        for name in &[
            "RS256",
            "PS256",
            "PS384",
            "PS512",
         ] {
            let public_key = load_file(match *name {
                "PS256" => "keys/rsapss_2048_sha256_public.der",
                "PS384" => "keys/rsapss_2048_sha384_public.der",
                "PS512" => "keys/rsapss_2048_sha512_public.der",
                _ => "keys/rsa_2048_public.der"
            })?;
            let alg = RsaAlgorithm::new(name, hash_algorithm(name));
            let _ = alg.verifier_from_der(&public_key)?;
        }
        Ok(())
    }

    #[test]
    fn load_public_pk1_pem() -> Result<()> {
        for name in &[
            "RS256",
         ] {
            let public_key = load_file(match *name {
                _ => "keys/rsa_2048_pk1_public.pem"
            })?;
            let alg = RsaAlgorithm::new(name, hash_algorithm(name));
            let _ = alg.verifier_from_pem(&public_key)?;
        }
        Ok(())
    }

    #[test]
    fn load_public_pk1_der() -> Result<()> {
        for name in &[
            "RS256",
         ] {
            let public_key = load_file(match *name {
                _ => "keys/rsa_2048_pk1_public.der"
            })?;
            let alg = RsaAlgorithm::new(name, hash_algorithm(name));
            let _ = alg.verifier_from_der(&public_key)?;
        }
        Ok(())
    }

    #[test]
    fn sign_and_verify_pem() -> Result<()> {
        let data = b"abcde12345";

        for name in &[
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
         ] {
            let alg = RsaAlgorithm::new(name, hash_algorithm(name));

            let private_key = load_file(match *name {
                "PS256" => "keys/rsapss_2048_sha256_private.pem",
                "PS384" => "keys/rsapss_2048_sha384_private.pem",
                "PS512" => "keys/rsapss_2048_sha512_private.pem",
                _ => "keys/rsa_2048_private.pem"
            })?;
            let public_key = load_file(match *name {
                "PS256" => "keys/rsapss_2048_sha256_public.pem",
                "PS384" => "keys/rsapss_2048_sha384_public.pem",
                "PS512" => "keys/rsapss_2048_sha512_public.pem",
                _ => "keys/rsa_2048_public.pem"
            })?;

            let signer = alg.signer_from_pem(&private_key)?;
            let signature = signer.sign(&[data])?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            verifier.verify(&[data], &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_der() -> Result<()> {
        let private_key = load_file("keys/rsa_2048_private.der")?;
        let public_key = load_file("keys/rsa_2048_public.der")?;
        let data = b"abcde12345";

        for name in &[
            "RS256",
            "RS384",
            "RS512",
        ] {
            let alg = RsaAlgorithm::new(name, hash_algorithm(name));

            let signer = alg.signer_from_der(&private_key)?;
            let signature = signer.sign(&[data])?;

            let verifier = alg.verifier_from_der(&public_key)?;
            verifier.verify(&[data], &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_pk1_pem() -> Result<()> {
        let private_key = load_file("keys/rsa_2048_pk1_private.pem")?;
        let public_key = load_file("keys/rsa_2048_pk1_public.pem")?;
        let data = b"abcde12345";

        for name in &[
            "RS256",
            "RS384",
            "RS512",
        ] {
            let alg = RsaAlgorithm::new(name, hash_algorithm(name));

            let signer = alg.signer_from_pem(&private_key)?;
            let signature = signer.sign(&[data])?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            verifier.verify(&[data], &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_pk1_der() -> Result<()> {
        let private_key = load_file("keys/rsa_2048_pk1_private.der")?;
        let public_key = load_file("keys/rsa_2048_pk1_public.der")?;
        let data = b"abcde12345";

        for name in &[
            "RS256",
            "RS384",
            "RS512",
        ] {
            let alg = RsaAlgorithm::new(name, hash_algorithm(name));

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

    fn hash_algorithm(name: &str) -> HashAlgorithm {
        match name {
            "RS256" | "PS256" => HashAlgorithm::SHA256,
            "RS384" | "PS384" => HashAlgorithm::SHA384,
            "RS512" | "PS512" => HashAlgorithm::SHA512,
            _ => unreachable!()
        }
    }
}

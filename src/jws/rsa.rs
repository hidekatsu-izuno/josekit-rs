use anyhow::{anyhow, bail};
use openssl::hash::MessageDigest;
use openssl::pkey::{HasPublic, PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::bn::BigNum;
use openssl::sign::{Signer, Verifier};
use serde_json::{Map, Value};

use crate::jws::{JwsAlgorithm, HashAlgorithm, JwsSigner, JwsVerifier};
use crate::jws::util::{json_eq, json_base64_bytes};
use crate::error::JwtError;

/// RSASSA-PKCS1-v1_5 using SHA-256
pub const RS256: RsaJwsAlgorithm = RsaJwsAlgorithm::new("RS256", HashAlgorithm::SHA256);

/// RSASSA-PKCS1-v1_5 using SHA-384
pub const RS384: RsaJwsAlgorithm = RsaJwsAlgorithm::new("RS384", HashAlgorithm::SHA384);

/// RSASSA-PKCS1-v1_5 using SHA-512
pub const RS512: RsaJwsAlgorithm = RsaJwsAlgorithm::new("RS512", HashAlgorithm::SHA512);

/// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
pub const PS256: RsaJwsAlgorithm = RsaJwsAlgorithm::new("PS256", HashAlgorithm::SHA256);

/// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
pub const PS384: RsaJwsAlgorithm = RsaJwsAlgorithm::new("PS384", HashAlgorithm::SHA384);

/// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
pub const PS512: RsaJwsAlgorithm = RsaJwsAlgorithm::new("PS512", HashAlgorithm::SHA512);

#[derive(Debug, Eq, PartialEq)]
pub struct RsaJwsAlgorithm {
    name: &'static str,
    hash_algorithm: HashAlgorithm,
}

impl RsaJwsAlgorithm {
    /// Return a new instance.
    ///
    /// # Arguments
    /// * `name` - A algrithm name.
    /// * `hash_algorithm` - A algrithm name.
    pub const fn new(name: &'static str, hash_algorithm: HashAlgorithm) -> Self {
        RsaJwsAlgorithm {
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
    ) -> Result<impl JwsSigner<Self> + 'a, JwtError> {
        (|| -> anyhow::Result<RsaJwsSigner> {
            let map: Map<String, Value> = serde_json::from_slice(data)?;

            json_eq(&map, "alg", &self.name())?;
            json_eq(&map, "kty", "RSA")?;
            json_eq(&map, "use", "sig")?;
            let n = json_base64_bytes(&map, "n")?;
            let e = json_base64_bytes(&map, "e")?;
            let d = json_base64_bytes(&map, "d")?;
            let p = json_base64_bytes(&map, "p")?;
            let q = json_base64_bytes(&map, "q")?;
            let dp = json_base64_bytes(&map, "dp")?;
            let dq = json_base64_bytes(&map, "dq")?;
            let qi = json_base64_bytes(&map, "qi")?;

            Rsa::from_private_components(
                BigNum::from_slice(&n)?,
                BigNum::from_slice(&e)?,
                BigNum::from_slice(&d)?,
                BigNum::from_slice(&p)?,
                BigNum::from_slice(&q)?,
                BigNum::from_slice(&dp)?,
                BigNum::from_slice(&dq)?,
                BigNum::from_slice(&qi)?
            )
                .and_then(|val| PKey::from_rsa(val))
                .map_err(|err| anyhow!(err))
                .map(|val| RsaJwsSigner {
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
    ) -> Result<impl JwsSigner<Self> + 'a, JwtError> {
        PKey::private_key_from_pem(&data)
            .or_else(|err| {
                Rsa::private_key_from_pem(&data)
                    .and_then(|val| PKey::from_rsa(val))
                    .map_err(|_| anyhow!(err))
            })
            .and_then(|pkey| (&self).check_key(pkey))
            .map_err(|err| JwtError::InvalidKeyFormat(err))
            .map(|val| RsaJwsSigner {
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
    ) -> Result<impl JwsSigner<Self> + 'a, JwtError> {
        PKey::private_key_from_der(&data)
            .or_else(|err| {
                Rsa::private_key_from_der(&data)
                    .and_then(|val| PKey::from_rsa(val))
                    .map_err(|_| anyhow!(err))
            })
            .and_then(|pkey| (&self).check_key(pkey))
            .map_err(|err| JwtError::InvalidKeyFormat(err))
            .map(|val| RsaJwsSigner {
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
    ) -> Result<impl JwsVerifier<Self> + 'a, JwtError> {
        (|| -> anyhow::Result<RsaJwsVerifier> {
            let map: Map<String, Value> = serde_json::from_slice(data)?;

            json_eq(&map, "alg", &self.name())?;
            json_eq(&map, "kty", "RSA")?;
            json_eq(&map, "use", "sig")?;
            let n = json_base64_bytes(&map, "n")?;
            let e = json_base64_bytes(&map, "e")?;

            Rsa::from_public_components(
                BigNum::from_slice(&n)?,
                BigNum::from_slice(&e)?,
            )
                .and_then(|val| PKey::from_rsa(val))
                .map_err(|err| anyhow!(err))
                .map(|val| RsaJwsVerifier {
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
    ) -> Result<impl JwsVerifier<Self> + 'a, JwtError> {
        PKey::public_key_from_pem(&data)
            .or_else(|err| {
                Rsa::public_key_from_pem_pkcs1(&data)
                    .and_then(|val| PKey::from_rsa(val))
                    .map_err(|_| anyhow!(err))
            })
            .and_then(|pkey| (&self).check_key(pkey))
            .map_err(|err| JwtError::InvalidKeyFormat(err))
            .map(|val| RsaJwsVerifier {
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
    ) -> Result<impl JwsVerifier<Self> + 'a, JwtError> {
        PKey::public_key_from_der(&data)
            .or_else(|err| {
                Rsa::public_key_from_der_pkcs1(&data)
                    .and_then(|val| PKey::from_rsa(val))
                    .map_err(|_| anyhow!(err))
            })
            .and_then(|pkey| (&self).check_key(pkey))
            .map_err(|err| JwtError::InvalidKeyFormat(err))
            .map(|val| RsaJwsVerifier {
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

    fn sign(&self, data: &[&[u8]]) -> Result<Vec<u8>, JwtError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let message_digest = match self.algorithm.hash_algorithm {
                HashAlgorithm::SHA256 => MessageDigest::sha256(),
                HashAlgorithm::SHA384 => MessageDigest::sha384(),
                HashAlgorithm::SHA512 => MessageDigest::sha512(),
            };

            let mut signer = Signer::new(message_digest, &self.private_key)?;
            for part in data {
                signer.update(part)?;
            }
            let signature = signer.sign_to_vec()?;
            Ok(signature)
        })()
        .map_err(|err| JwtError::InvalidSignature(err))
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

    fn verify(&self, data: &[&[u8]], signature: &[u8]) -> Result<(), JwtError> {
        (|| -> anyhow::Result<()> {
            let message_digest = match self.algorithm.hash_algorithm {
                HashAlgorithm::SHA256 => MessageDigest::sha256(),
                HashAlgorithm::SHA384 => MessageDigest::sha384(),
                HashAlgorithm::SHA512 => MessageDigest::sha512(),
            };

            let mut verifier = Verifier::new(message_digest, &self.public_key)?;
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
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
         ] {
            let alg = RsaJwsAlgorithm::new(name, hash_algorithm(name));

            let private_key = load_file(match *name {
                "RS256" => "jwk/rs256_private.jwk",
                "RS384" => "jwk/rs384_private.jwk",
                "RS512" => "jwk/rs512_private.jwk",
                "PS256" => "jwk/ps256_private.jwk",
                "PS384" => "jwk/ps384_private.jwk",
                "PS512" => "jwk/ps512_private.jwk",
                _ => unreachable!()
            })?;
            let public_key = load_file(match *name {
                "RS256" => "jwk/rs256_public.jwk",
                "RS384" => "jwk/rs384_public.jwk",
                "RS512" => "jwk/rs512_public.jwk",
                "PS256" => "jwk/ps256_public.jwk",
                "PS384" => "jwk/ps384_public.jwk",
                "PS512" => "jwk/ps512_public.jwk",
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
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
         ] {
            let alg = RsaJwsAlgorithm::new(name, hash_algorithm(name));

            let private_key = load_file(match *name {
                "PS256" => "pem/rsapss_2048_sha256_pkcs8_private.pem",
                "PS384" => "pem/rsapss_2048_sha384_pkcs8_private.pem",
                "PS512" => "pem/rsapss_2048_sha512_pkcs8_private.pem",
                _ => "pem/rsa_2048_pkcs8_private.pem"
            })?;
            let public_key = load_file(match *name {
                "PS256" => "pem/rsapss_2048_sha256_pkcs8_public.pem",
                "PS384" => "pem/rsapss_2048_sha384_pkcs8_public.pem",
                "PS512" => "pem/rsapss_2048_sha512_pkcs8_public.pem",
                _ => "pem/rsa_2048_pkcs8_public.pem"
            })?;

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
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
         ] {
            let alg = RsaJwsAlgorithm::new(name, hash_algorithm(name));

            let private_key = load_file(match *name {
                "PS256" => "der/rsapss_2048_sha256_pkcs8_private.der",
                "PS384" => "der/rsapss_2048_sha384_pkcs8_private.der",
                "PS512" => "der/rsapss_2048_sha512_pkcs8_private.der",
                _ => "der/rsa_2048_pkcs8_private.der"
            })?;
            let public_key = load_file(match *name {
                "PS256" => "der/rsapss_2048_sha256_pkcs8_public.der",
                "PS384" => "der/rsapss_2048_sha384_pkcs8_public.der",
                "PS512" => "der/rsapss_2048_sha512_pkcs8_public.der",
                _ => "der/rsa_2048_pkcs8_public.der"
            })?;

            let signer = alg.signer_from_der(&private_key)?;
            let signature = signer.sign(&[data])?;

            let verifier = alg.verifier_from_der(&public_key)?;
            verifier.verify(&[data], &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_pkcs1_pem() -> Result<()> {
        let data = b"abcde12345";

        for name in &[
            "RS256",
            "RS384",
            "RS512",
            //"PS256",
            //"PS384",
            //"PS512",
         ] {
            let alg = RsaJwsAlgorithm::new(name, hash_algorithm(name));

            let private_key = load_file(match *name {
                "PS256" => "pem/rsapss_2048_sha256_pkcs1_private.pem",
                "PS384" => "pem/rsapss_2048_sha384_pkcs1_private.pem",
                "PS512" => "pem/rsapss_2048_sha512_pkcs1_private.pem",
                _ => "pem/rsa_2048_pkcs1_private.pem"
            })?;
            let public_key = load_file(match *name {
                "PS256" => "pem/rsapss_2048_sha256_pkcs1_public.pem",
                "PS384" => "pem/rsapss_2048_sha384_pkcs1_public.pem",
                "PS512" => "pem/rsapss_2048_sha512_pkcs1_public.pem",
                _ => "pem/rsa_2048_pkcs1_public.pem"
            })?;

            let signer = alg.signer_from_pem(&private_key)?;
            let signature = signer.sign(&[data])?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            verifier.verify(&[data], &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_pkcs1_der() -> Result<()> {
        let data = b"abcde12345";

        for name in &[
            "RS256",
            "RS384",
            "RS512",
            //"PS256",
            //"PS384",
            //"PS512",
         ] {
            let alg = RsaJwsAlgorithm::new(name, hash_algorithm(name));

            let private_key = load_file(match *name {
                "PS256" => "der/rsapss_2048_sha256_pkcs1_private.der",
                "PS384" => "der/rsapss_2048_sha384_pkcs1_private.der",
                "PS512" => "der/rsapss_2048_sha512_pkcs1_private.der",
                _ => "der/rsa_2048_pkcs1_private.der"
            })?;
            let public_key = load_file(match *name {
                "PS256" => "der/rsapss_2048_sha256_pkcs1_public.der",
                "PS384" => "der/rsapss_2048_sha384_pkcs1_public.der",
                "PS512" => "der/rsapss_2048_sha512_pkcs1_public.der",
                _ => "der/rsa_2048_pkcs1_public.der"
            })?;

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

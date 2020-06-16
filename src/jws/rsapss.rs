use anyhow::bail;
use std::io::Read;
use openssl::hash::MessageDigest;
use openssl::pkey::{HasPublic, PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::bn::BigNum;
use openssl::sign::{Signer, Verifier};
use serde_json::{Map, Value};
use once_cell::sync::Lazy;

use crate::jws::{JwsAlgorithm, JwsSigner, JwsVerifier};
use crate::jws::util::{json_eq, json_base64_bytes};
use crate::der::{DerReader, DerBuilder, DerType, DerError};
use crate::der::oid::{ObjectIdentifier};
use crate::error::JoseError;

/// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
pub const PS256: RsaPssJwsAlgorithm = RsaPssJwsAlgorithm::new("PS256");

/// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
pub const PS384: RsaPssJwsAlgorithm = RsaPssJwsAlgorithm::new("PS384");

/// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
pub const PS512: RsaPssJwsAlgorithm = RsaPssJwsAlgorithm::new("PS512");

static OID_RSASSA_PSS: Lazy<ObjectIdentifier> = Lazy::new(|| {
    ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 10])
});

#[derive(Debug, Eq, PartialEq)]
pub struct RsaPssJwsAlgorithm {
    name: &'static str,
}

impl RsaPssJwsAlgorithm {
    /// Return a new instance.
    ///
    /// # Arguments
    /// * `name` - A algrithm name.
    const fn new(name: &'static str) -> Self {
        RsaPssJwsAlgorithm {
            name,
        }
    }

    /// Return a signer from a private key of JWK format.
    ///
    /// # Arguments
    /// * `input` - A private key of JWK format.
    pub fn signer_from_jwk<'a>(
        &'a self,
        input: &[u8],
    ) -> Result<impl JwsSigner<Self> + 'a, JoseError> {
        (|| -> anyhow::Result<RsaPssJwsSigner> {
            let map: Map<String, Value> = serde_json::from_slice(input)?;

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

            let pkey = Rsa::from_private_components(
                BigNum::from_slice(&n)?,
                BigNum::from_slice(&e)?,
                BigNum::from_slice(&d)?,
                BigNum::from_slice(&p)?,
                BigNum::from_slice(&q)?,
                BigNum::from_slice(&dp)?,
                BigNum::from_slice(&dq)?,
                BigNum::from_slice(&qi)?
            ).and_then(|val| PKey::from_rsa(val))?;

            self.check_key(&pkey)?;

            Ok(RsaPssJwsSigner {
                algorithm: &self,
                private_key: pkey,
            })
        })().map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a signer from a private key of PKCS#1 or PKCS#8 PEM format.
    ///
    /// # Arguments
    /// * `input` - A private key of PKCS#1 or PKCS#8 PEM format.
    pub fn signer_from_pem<'a>(
        &'a self,
        input: &[u8],
    ) -> Result<impl JwsSigner<Self> + 'a, JoseError> {
        (|| -> anyhow::Result<RsaPssJwsSigner> {
            let pkey = PKey::private_key_from_pem(&input)
                .or_else(|err| {
                    Rsa::private_key_from_pem(&input)
                        .and_then(|val| PKey::from_rsa(val))
                        .map_err(|_| err)
                })?;

            self.check_key(&pkey)?;

            Ok(RsaPssJwsSigner {
                algorithm: &self,
                private_key: pkey,
            })
        })().map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a signer from a private key of PKCS#1 or PKCS#8 DER format.
    ///
    /// # Arguments
    /// * `input` - A private key of PKCS#1 or PKCS#8 DER format.
    pub fn signer_from_der<'a>(
        &'a self,
        input: &'a [u8],
    ) -> Result<impl JwsSigner<Self> + 'a, JoseError> {
        (|| -> anyhow::Result<RsaPssJwsSigner> {
            let tmp_input;
            let input = if Self::is_private_pkcs8(input) {
                input
            } else {
                tmp_input = Self::to_private_pkcs8(input);
                &tmp_input
            };

            let pkey = PKey::private_key_from_der(&input)?;
            self.check_key(&pkey)?;

            Ok(RsaPssJwsSigner {
                algorithm: &self,
                private_key: pkey,
            })
        })().map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a key of JWK format.
    ///
    /// # Arguments
    /// * `input` - A key of JWK format.
    pub fn verifier_from_jwk<'a>(
        &'a self,
        input: &[u8],
    ) -> Result<impl JwsVerifier<Self> + 'a, JoseError> {
        (|| -> anyhow::Result<RsaPssJwsVerifier> {
            let map: Map<String, Value> = serde_json::from_slice(input)?;

            json_eq(&map, "alg", &self.name())?;
            json_eq(&map, "kty", "RSA")?;
            json_eq(&map, "use", "sig")?;
            let n = json_base64_bytes(&map, "n")?;
            let e = json_base64_bytes(&map, "e")?;

            let pkey = Rsa::from_public_components(
                BigNum::from_slice(&n)?,
                BigNum::from_slice(&e)?,
            ).and_then(|val| PKey::from_rsa(val))?;

            self.check_key(&pkey)?;

            Ok(RsaPssJwsVerifier {
                algorithm: &self,
                public_key: pkey,
            })
        })().map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a public key of PKCS#1 or PKCS#8 PEM format.
    ///
    /// # Arguments
    /// * `input` - A public key of PKCS#1 or PKCS#8 PEM format.
    pub fn verifier_from_pem<'a>(
        &'a self,
        input: &[u8],
    ) -> Result<impl JwsVerifier<Self> + 'a, JoseError> {
        (|| -> anyhow::Result<RsaPssJwsVerifier> {
            let pkey = PKey::public_key_from_pem(&input)
                .or_else(|err| {
                    Rsa::public_key_from_pem_pkcs1(&input)
                        .and_then(|val| PKey::from_rsa(val))
                        .map_err(|_| err)
                })?;

            self.check_key(&pkey)?;

            Ok(RsaPssJwsVerifier {
                algorithm: &self,
                public_key: pkey,
            })
        })().map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a public key of PKCS#1 or PKCS#8 DER format.
    ///
    /// # Arguments
    /// * `input` - A public key of PKCS#1 or PKCS#8 DER format.
    pub fn verifier_from_der<'a>(
        &'a self,
        input: &[u8],
    ) -> Result<impl JwsVerifier<Self> + 'a, JoseError> {
        (|| -> anyhow::Result<RsaPssJwsVerifier> {
            let tmp_input;
            let input = if Self::is_public_pkcs8(input) {
                input
            } else {
                tmp_input = Self::to_public_pkcs8(input);
                &tmp_input
            };

            let pkey = PKey::public_key_from_der(&input)?;
            self.check_key(&pkey)?;

            Ok(RsaPssJwsVerifier {
                algorithm: &self,
                public_key: pkey,
            })
        })().map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn check_key<T>(&self, pkey: &PKey<T>) -> anyhow::Result<()>
    where
        T: HasPublic,
    {
        let rsa = pkey.rsa()?;

        if rsa.size() * 8 < 2048 {
            bail!("key length must be 2048 or more.");
        }

        Ok(())
    }

    fn is_private_pkcs8(input: &[u8]) -> bool {
        let mut reader = DerReader::new(input.bytes());

        (|| -> Result<bool, DerError> {
            match reader.next()? {
                Some(DerType::Sequence) => {},
                _ => return Ok(false)
            }

            // Version
            match reader.next()? {
                Some(DerType::Integer) => {
                    match reader.to_u8() {
                        Ok(val) if val == 0 => {},
                        _ => return Ok(false)
                    }
                },
                _ => return Ok(false)
            }

            match reader.next()? {
                Some(DerType::Sequence) => {},
                _ => return Ok(false)
            }

            match reader.next()? {
                Some(DerType::ObjectIdentifier) => {
                    match reader.to_object_identifier() {
                        Ok(val) if val == *OID_RSASSA_PSS => {},
                        _ => return Ok(false)
                    }
                },
                _ => return Ok(false)
            }

            Ok(true)
        })().unwrap_or(false)
    }

    fn to_private_pkcs8(input: &[u8]) -> Vec<u8> {
        let mut builder = DerBuilder::new();
        builder.begin(DerType::Sequence);
        {
            builder.append_integer_from_u8(0);
            builder.begin(DerType::Sequence);
            {
                builder.append_object_identifier(&OID_RSASSA_PSS);
                builder.append_null();
            }
            builder.end();
        }
        builder.append_octed_string_from_slice(input);
        builder.end();
        builder.build()
    }

    fn is_public_pkcs8(input: &[u8]) -> bool {
        let mut reader = DerReader::new(input.bytes());

        (|| -> Result<bool, DerError> {
            match reader.next()? {
                Some(DerType::Sequence) => {},
                _ => return Ok(false)
            }

            match reader.next()? {
                Some(DerType::Sequence) => {},
                _ => return Ok(false)
            }

            match reader.next()? {
                Some(DerType::ObjectIdentifier) => {
                    match reader.to_object_identifier() {
                        Ok(val) if val == *OID_RSASSA_PSS => {},
                        _ => return Ok(false)
                    }
                },
                _ => return Ok(false)
            }

            Ok(true)
        })().unwrap_or(false)
    }

    fn to_public_pkcs8(input: &[u8]) -> Vec<u8> {
        let mut builder = DerBuilder::new();
        builder.begin(DerType::Sequence);
        {
            builder.begin(DerType::Sequence);
            {
                builder.append_object_identifier(&OID_RSASSA_PSS);
                builder.append_null();
            }
            builder.end();
        }
        builder.append_bit_string_from_slice(input, 0);
        builder.end();
        builder.build()
    }
}

impl JwsAlgorithm for RsaPssJwsAlgorithm {
    fn name(&self) -> &str {
        self.name
    }
}

pub struct RsaPssJwsSigner<'a> {
    algorithm: &'a RsaPssJwsAlgorithm,
    private_key: PKey<Private>,
}

impl<'a> JwsSigner<RsaPssJwsAlgorithm> for RsaPssJwsSigner<'a> {
    fn algorithm(&self) -> &RsaPssJwsAlgorithm {
        &self.algorithm
    }

    fn sign(&self, input: &[&[u8]]) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let message_digest = match self.algorithm.name {
                "RS256" | "PS256" => MessageDigest::sha256(),
                "RS384" | "PS384" => MessageDigest::sha384(),
                "RS512" | "PS512" => MessageDigest::sha512(),
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

pub struct RsaPssJwsVerifier<'a> {
    algorithm: &'a RsaPssJwsAlgorithm,
    public_key: PKey<Public>,
}

impl<'a> JwsVerifier<RsaPssJwsAlgorithm> for RsaPssJwsVerifier<'a> {
    fn algorithm(&self) -> &RsaPssJwsAlgorithm {
        &self.algorithm
    }

    fn verify(&self, input: &[&[u8]], signature: &[u8]) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            let message_digest = match self.algorithm.name {
                "RS256" | "PS256" => MessageDigest::sha256(),
                "RS384" | "PS384" => MessageDigest::sha384(),
                "RS512" | "PS512" => MessageDigest::sha512(),
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
    fn sign_and_verify_rsspss_jwt() -> Result<()> {
        let data = b"abcde12345";

        for name in &[
            "PS256",
            "PS384",
            "PS512",
         ] {
            let alg = RsaPssJwsAlgorithm::new(name);

            let private_key = load_file(match *name {
                "PS256" => "jwk/ps256_private.jwk",
                "PS384" => "jwk/ps384_private.jwk",
                "PS512" => "jwk/ps512_private.jwk",
                _ => unreachable!()
            })?;
            let public_key = load_file(match *name {
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
    fn sign_and_verify_rsspss_pkcs8_pem() -> Result<()> {
        let data = b"abcde12345";

        for name in &[
            "PS256",
            "PS384",
            "PS512",
         ] {
            let alg = RsaPssJwsAlgorithm::new(name);

            let private_key = load_file(match *name {
                "PS256" => "pem/rsapss_2048_sha256_pkcs8_private.pem",
                "PS384" => "pem/rsapss_2048_sha384_pkcs8_private.pem",
                "PS512" => "pem/rsapss_2048_sha512_pkcs8_private.pem",
                _ => unreachable!()
            })?;
            let public_key = load_file(match *name {
                "PS256" => "pem/rsapss_2048_sha256_pkcs8_public.pem",
                "PS384" => "pem/rsapss_2048_sha384_pkcs8_public.pem",
                "PS512" => "pem/rsapss_2048_sha512_pkcs8_public.pem",
                _ => unreachable!()
            })?;

            let signer = alg.signer_from_pem(&private_key)?;
            let signature = signer.sign(&[data])?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            verifier.verify(&[data], &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsspss_pkcs8_der() -> Result<()> {
        let data = b"abcde12345";

        for name in &[
            "RS256",
            "RS384",
            "RS512",
            "PS256",
            "PS384",
            "PS512",
         ] {
            let alg = RsaPssJwsAlgorithm::new(name);

            let private_key = load_file(match *name {
                "PS256" => "der/rsapss_2048_sha256_pkcs8_private.der",
                "PS384" => "der/rsapss_2048_sha384_pkcs8_private.der",
                "PS512" => "der/rsapss_2048_sha512_pkcs8_private.der",
                _ => unreachable!()
            })?;
            let public_key = load_file(match *name {
                "PS256" => "der/rsapss_2048_sha256_pkcs8_public.der",
                "PS384" => "der/rsapss_2048_sha384_pkcs8_public.der",
                "PS512" => "der/rsapss_2048_sha512_pkcs8_public.der",
                _ => unreachable!()
            })?;

            let signer = alg.signer_from_der(&private_key)?;
            let signature = signer.sign(&[data])?;

            let verifier = alg.verifier_from_der(&public_key)?;
            verifier.verify(&[data], &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsspss_pkcs1_pem() -> Result<()> {
        let data = b"abcde12345";

        for name in &[
            "PS256",
            "PS384",
            "PS512",
         ] {
            let alg = RsaPssJwsAlgorithm::new(name);

            let private_key = load_file(match *name {
                "PS256" => "pem/rsapss_2048_sha256_pkcs1_private.pem",
                "PS384" => "pem/rsapss_2048_sha384_pkcs1_private.pem",
                "PS512" => "pem/rsapss_2048_sha512_pkcs1_private.pem",
                _ => unreachable!()
            })?;
            let public_key = load_file(match *name {
                "PS256" => "pem/rsapss_2048_sha256_pkcs1_public.pem",
                "PS384" => "pem/rsapss_2048_sha384_pkcs1_public.pem",
                "PS512" => "pem/rsapss_2048_sha512_pkcs1_public.pem",
                _ => unreachable!()
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
            "PS256",
            "PS384",
            "PS512",
         ] {
            let alg = RsaPssJwsAlgorithm::new(name);

            let private_key = load_file(match *name {
                "PS256" => "der/rsapss_2048_sha256_pkcs1_private.der",
                "PS384" => "der/rsapss_2048_sha384_pkcs1_private.der",
                "PS512" => "der/rsapss_2048_sha512_pkcs1_private.der",
                _ => unreachable!()
            })?;
            let public_key = load_file(match *name {
                "PS256" => "der/rsapss_2048_sha256_pkcs1_public.der",
                "PS384" => "der/rsapss_2048_sha384_pkcs1_public.der",
                "PS512" => "der/rsapss_2048_sha512_pkcs1_public.der",
                _ => unreachable!()
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
}

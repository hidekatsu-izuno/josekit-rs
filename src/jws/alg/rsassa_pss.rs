use std::ops::{Deref, DerefMut};

use anyhow::bail;
use openssl::hash::MessageDigest;
use openssl::pkey::{HasPublic, PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use serde_json::Value;

use crate::der::{DerBuilder, DerType};
use crate::jose::JoseError;
use crate::jwk::{Jwk, KeyPair, RsaPssKeyPair};
use crate::jws::{JwsAlgorithm, JwsSigner, JwsVerifier};
use crate::util;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum RsassaPssJwsAlgorithm {
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    PS256,
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    PS384,
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    PS512,
}

impl RsassaPssJwsAlgorithm {
    /// Generate RSA key pair.
    ///
    /// # Arguments
    /// * `bits` - RSA key length
    pub fn generate_keypair(&self, bits: u32) -> Result<RsaPssKeyPair, JoseError> {
        let mut keypair = RsaPssKeyPair::generate(
            bits,
            self.message_digest(),
            self.message_digest(),
            self.salt_len(),
        )?;
        keypair.set_algorithm(Some(self.name()));
        Ok(keypair)
    }

    /// Create a RSA-PSS key pair from a private key that is a DER encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey.
    pub fn keypair_from_der(&self, input: impl AsRef<[u8]>) -> Result<RsaPssKeyPair, JoseError> {
        (|| -> anyhow::Result<RsaPssKeyPair> {
            let pkcs8;
            let pkcs8_ref = match RsaPssKeyPair::detect_pkcs8(input.as_ref(), false) {
                Some((md, mgf1_md, salt_len)) => {
                    if md != self.message_digest() {
                        bail!("The message digest parameter is mismatched: {}", md);
                    } else if mgf1_md != self.message_digest() {
                        bail!("The mgf1 message digest parameter is mismatched: {}", mgf1_md);
                    } else if salt_len != self.salt_len() {
                        bail!("The salt size is mismatched: {}", salt_len);
                    }

                    input.as_ref()
                },
                None => {
                    pkcs8 = RsaPssKeyPair::to_pkcs8(
                        input.as_ref(),
                        false,
                        self.message_digest(),
                        self.message_digest(),
                        self.salt_len(),
                    );
                    &pkcs8
                }
            };

            let private_key = PKey::private_key_from_der(pkcs8_ref)?;
            self.check_key(&private_key)?;

            let mut keypair = RsaPssKeyPair::from_private_key(
                private_key,
                self.message_digest(),
                self.message_digest(),
                self.salt_len(),
            );
            keypair.set_algorithm(Some(self.name()));
            Ok(keypair)
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Create a RSA-PSS key pair from a private key of common or traditinal PEM format.
    ///
    /// Common PEM format is a DER and base64 encoded PKCS#8 PrivateKeyInfo
    /// that surrounded by "-----BEGIN/END PRIVATE KEY----".
    ///
    /// Traditional PEM format is a DER and base64 encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey
    /// that surrounded by "-----BEGIN/END RSA-PSS/RSA PRIVATE KEY----".
    ///
    /// # Arguments
    /// * `input` - A private key of common or traditinal PEM format.
    pub fn keypair_from_pem(&self, input: impl AsRef<[u8]>) -> Result<RsaPssKeyPair, JoseError> {
        (|| -> anyhow::Result<RsaPssKeyPair> {
            let (alg, data) = util::parse_pem(input.as_ref())?;

            let private_key = match alg.as_str() {
                "PRIVATE KEY" | "RSA-PSS PRIVATE KEY" => {
                    match RsaPssKeyPair::detect_pkcs8(&data, false) {
                        Some((md, mgf1_md, salt_len)) => {
                            if md != self.message_digest() {
                                bail!("The message digest parameter is mismatched: {}", md);
                            } else if mgf1_md != self.message_digest() {
                                bail!("The mgf1 message digest parameter is mismatched: {}", mgf1_md);
                            } else if salt_len != self.salt_len() {
                                bail!("The salt size is mismatched: {}", salt_len);
                            }

                            PKey::private_key_from_der(&data)?
                        },
                        None => bail!("Invalid PEM contents."),
                    }
                }
                "RSA PRIVATE KEY" => {
                    let pkcs8 = RsaPssKeyPair::to_pkcs8(
                        &data,
                        false,
                        self.message_digest(),
                        self.message_digest(),
                        self.salt_len(),
                    );
                    PKey::private_key_from_der(&pkcs8)?
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };
            self.check_key(&private_key)?;

            let mut keypair = RsaPssKeyPair::from_private_key(
                private_key,
                self.message_digest(),
                self.message_digest(),
                self.salt_len(),
            );
            keypair.set_algorithm(Some(self.name()));
            Ok(keypair)
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a signer from a private key that is a DER encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey.
    pub fn signer_from_der(&self, input: impl AsRef<[u8]>) -> Result<RsassaPssJwsSigner, JoseError> {
        let keypair = self.keypair_from_der(input.as_ref())?;
        Ok(RsassaPssJwsSigner {
            algorithm: self.clone(),
            private_key: keypair.into_private_key(),
            key_id: None,
        })
    }

    /// Return a signer from a private key of common or traditinal PEM format.
    ///
    /// Common PEM format is a DER and base64 encoded PKCS#8 PrivateKeyInfo
    /// that surrounded by "-----BEGIN/END PRIVATE KEY----".
    ///
    /// Traditional PEM format is a DER and base64 encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey
    /// that surrounded by "-----BEGIN/END RSA-PSS/RSA PRIVATE KEY----".
    ///
    /// # Arguments
    /// * `input` - A private key of common or traditinal PEM format.
    pub fn signer_from_pem(&self, input: impl AsRef<[u8]>) -> Result<RsassaPssJwsSigner, JoseError> {
        let keypair = self.keypair_from_pem(input.as_ref())?;
        Ok(RsassaPssJwsSigner {
            algorithm: self.clone(),
            private_key: keypair.into_private_key(),
            key_id: None,
        })
    }

    /// Return a signer from a private key that is formatted by a JWK of RSA type.
    ///
    /// # Arguments
    /// * `jwk` - A private key that is formatted by a JWK of RSA type.
    pub fn signer_from_jwk(&self, jwk: &Jwk) -> Result<RsassaPssJwsSigner, JoseError> {
        (|| -> anyhow::Result<RsassaPssJwsSigner> {
            match jwk.key_type() {
                val if val == "RSA" => {}
                val => bail!("A parameter kty must be RSA: {}", val),
            }
            match jwk.key_use() {
                Some(val) if val == "sig" => {}
                None => {}
                Some(val) => bail!("A parameter use must be sig: {}", val),
            }
            if !jwk.is_for_key_operation("sign") {
                bail!("A parameter key_ops must contains sign.");
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }
            let key_id = jwk.key_id();

            let n = match jwk.parameter("n") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter n must be a string."),
                None => bail!("A parameter n is required."),
            };
            let e = match jwk.parameter("e") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter e must be a string."),
                None => bail!("A parameter e is required."),
            };
            let d = match jwk.parameter("d") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter d must be a string."),
                None => bail!("A parameter d is required."),
            };
            let p = match jwk.parameter("p") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter p must be a string."),
                None => bail!("A parameter p is required."),
            };
            let q = match jwk.parameter("q") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter q must be a string."),
                None => bail!("A parameter q is required."),
            };
            let dp = match jwk.parameter("dp") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter dp must be a string."),
                None => bail!("A parameter dp is required."),
            };
            let dq = match jwk.parameter("dq") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter dq must be a string."),
                None => bail!("A parameter dq is required."),
            };
            let qi = match jwk.parameter("qi") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter qi must be a string."),
                None => bail!("A parameter qi is required."),
            };

            let mut builder = DerBuilder::new();
            builder.begin(DerType::Sequence);
            {
                builder.append_integer_from_u8(0); // version
                builder.append_integer_from_be_slice(&n, false); // n
                builder.append_integer_from_be_slice(&e, false); // e
                builder.append_integer_from_be_slice(&d, false); // d
                builder.append_integer_from_be_slice(&p, false); // p
                builder.append_integer_from_be_slice(&q, false); // q
                builder.append_integer_from_be_slice(&dp, false); // d mod (p-1)
                builder.append_integer_from_be_slice(&dq, false); // d mod (q-1)
                builder.append_integer_from_be_slice(&qi, false); // (inverse of q) mod p
            }
            builder.end();

            let pkcs8 = RsaPssKeyPair::to_pkcs8(
                &builder.build(),
                false,
                self.message_digest(),
                self.message_digest(),
                self.salt_len(),
            );
            let pkey = PKey::private_key_from_der(&pkcs8)?;
            self.check_key(&pkey)?;

            Ok(RsassaPssJwsSigner {
                algorithm: self.clone(),
                private_key: pkey,
                key_id: key_id.map(|val| val.to_string()),
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a public key that is a DER encoded SubjectPublicKeyInfo or PKCS#1 RSAPublicKey.
    ///
    /// # Arguments
    /// * `input` - A public key that is a DER encoded SubjectPublicKeyInfo or PKCS#1 RSAPublicKey.
    pub fn verifier_from_der(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<RsassaPssJwsVerifier, JoseError> {
        (|| -> anyhow::Result<RsassaPssJwsVerifier> {
            let pkcs8;
            let pkcs8_ref = match RsaPssKeyPair::detect_pkcs8(input.as_ref(), true) {
                Some((md, mgf1_md, salt_len)) => {
                    if md != self.message_digest() {
                        bail!("The message digest parameter is mismatched: {}", md);
                    } else if mgf1_md != self.message_digest() {
                        bail!("The mgf1 message digest parameter is mismatched: {}", mgf1_md);
                    } else if salt_len != self.salt_len() {
                        bail!("The salt size is mismatched: {}", salt_len);
                    }
                    
                    input.as_ref()
                },
                None => {
                    pkcs8 = RsaPssKeyPair::to_pkcs8(
                        input.as_ref(),
                        true,
                        self.message_digest(),
                        self.message_digest(),
                        self.salt_len(),
                    );
                    &pkcs8
                }
            };

            let public_key = PKey::public_key_from_der(pkcs8_ref)?;

            self.check_key(&public_key)?;

            Ok(RsassaPssJwsVerifier {
                algorithm: self.clone(),
                public_key,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a key of common or traditional PEM format.
    ///
    /// Common PEM format is a DER and base64 encoded SubjectPublicKeyInfo
    /// that surrounded by "-----BEGIN/END PUBLIC KEY----".
    ///
    /// Traditional PEM format is a DER and base64 SubjectPublicKeyInfo or PKCS#1 RSAPublicKey
    /// that surrounded by "-----BEGIN/END RSA-PSS/RSA PUBLIC KEY----".
    ///
    /// # Arguments
    /// * `input` - A public key of common or traditional PEM format.
    pub fn verifier_from_pem(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<RsassaPssJwsVerifier, JoseError> {
        (|| -> anyhow::Result<RsassaPssJwsVerifier> {
            let (alg, data) = util::parse_pem(input.as_ref())?;
            let public_key = match alg.as_str() {
                "PUBLIC KEY" | "RSA-PSS PUBLIC KEY" => {
                    match RsaPssKeyPair::detect_pkcs8(&data, true) {
                        Some((md, mgf1_md, salt_len)) => {
                            if md != self.message_digest() {
                                bail!("The message digest parameter is mismatched: {}", md);
                            } else if mgf1_md != self.message_digest() {
                                bail!("The mgf1 message digest parameter is mismatched: {}", mgf1_md);
                            } else if salt_len != self.salt_len() {
                                bail!("The salt size is mismatched: {}", salt_len);
                            }
                            
                            PKey::public_key_from_der(&data)?
                        },
                        None => bail!("Invalid PEM contents."),
                    }
                }
                "RSA PUBLIC KEY" => {
                    let pkcs8 = RsaPssKeyPair::to_pkcs8(
                        &data,
                        true,
                        self.message_digest(),
                        self.message_digest(),
                        self.salt_len(),
                    );
                    PKey::public_key_from_der(&pkcs8)?
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };

            self.check_key(&public_key)?;

            Ok(RsassaPssJwsVerifier {
                algorithm: self.clone(),
                public_key,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a public key that is formatted by a JWK of RSA type.
    ///
    /// # Arguments
    /// * `jwk` - A public key that is formatted by a JWK of RSA type.
    pub fn verifier_from_jwk(&self, jwk: &Jwk) -> Result<RsassaPssJwsVerifier, JoseError> {
        (|| -> anyhow::Result<RsassaPssJwsVerifier> {
            match jwk.key_type() {
                val if val == "RSA" => {}
                val => bail!("A parameter kty must be RSA: {}", val),
            };
            match jwk.key_use() {
                Some(val) if val == "sig" => {}
                None => {}
                Some(val) => bail!("A parameter use must be sig: {}", val),
            };
            if !jwk.is_for_key_operation("verify") {
                bail!("A parameter key_ops must contains verify.");
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }
            let n = match jwk.parameter("n") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter n must be a string."),
                None => bail!("A parameter n is required."),
            };
            let e = match jwk.parameter("e") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter e must be a string."),
                None => bail!("A parameter e is required."),
            };

            let mut builder = DerBuilder::new();
            builder.begin(DerType::Sequence);
            {
                builder.append_integer_from_be_slice(&n, false); // n
                builder.append_integer_from_be_slice(&e, false); // e
            }
            builder.end();

            let pkcs8 = RsaPssKeyPair::to_pkcs8(
                &builder.build(),
                true,
                self.message_digest(),
                self.message_digest(),
                self.salt_len(),
            );
            let public_key = PKey::public_key_from_der(&pkcs8)?;
            let key_id = jwk.key_id().map(|val| val.to_string());

            self.check_key(&public_key)?;

            Ok(RsassaPssJwsVerifier {
                algorithm: self.clone(),
                public_key,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn message_digest(&self) -> util::MessageDigest {
        match self {
            RsassaPssJwsAlgorithm::PS256 => util::MessageDigest::Sha256,
            RsassaPssJwsAlgorithm::PS384 => util::MessageDigest::Sha384,
            RsassaPssJwsAlgorithm::PS512 => util::MessageDigest::Sha512,
        }
    }

    fn salt_len(&self) -> u8 {
        match self {
            RsassaPssJwsAlgorithm::PS256 => 32,
            RsassaPssJwsAlgorithm::PS384 => 48,
            RsassaPssJwsAlgorithm::PS512 => 64,
        }
    }

    fn check_key<T: HasPublic>(&self, pkey: &PKey<T>) -> anyhow::Result<()> {
        let rsa = pkey.rsa()?;

        if rsa.size() * 8 < 2048 {
            bail!("key length must be 2048 or more.");
        }

        Ok(())
    }
}

impl JwsAlgorithm for RsassaPssJwsAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::PS256 => "PS256",
            Self::PS384 => "PS384",
            Self::PS512 => "PS512",
        }
    }

    fn box_clone(&self) -> Box<dyn JwsAlgorithm> {
        Box::new(self.clone())
    }
}

impl Deref for RsassaPssJwsAlgorithm {
    type Target = dyn JwsAlgorithm;

    fn deref(&self) -> &Self::Target {
        self
    }
}

impl DerefMut for RsassaPssJwsAlgorithm {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct RsassaPssJwsSigner {
    algorithm: RsassaPssJwsAlgorithm,
    private_key: PKey<Private>,
    key_id: Option<String>,
}

impl JwsSigner for RsassaPssJwsSigner {
    fn algorithm(&self) -> &dyn JwsAlgorithm {
        &self.algorithm
    }

    fn signature_len(&self) -> usize {
        256
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn set_key_id(&mut self, key_id: &str) {
        self.key_id = Some(key_id.to_string());
    }

    fn remove_key_id(&mut self) {
        self.key_id = None;
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let message_digest = match self.algorithm {
                RsassaPssJwsAlgorithm::PS256 => MessageDigest::sha256(),
                RsassaPssJwsAlgorithm::PS384 => MessageDigest::sha384(),
                RsassaPssJwsAlgorithm::PS512 => MessageDigest::sha512(),
            };

            let mut signer = Signer::new(message_digest, &self.private_key)?;
            signer.update(message)?;
            let signature = signer.sign_to_vec()?;
            Ok(signature)
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }

    fn box_clone(&self) -> Box<dyn JwsSigner> {
        Box::new(self.clone())
    }
}

impl Deref for RsassaPssJwsSigner {
    type Target = dyn JwsSigner;

    fn deref(&self) -> &Self::Target {
        self
    }
}

impl DerefMut for RsassaPssJwsSigner {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct RsassaPssJwsVerifier {
    algorithm: RsassaPssJwsAlgorithm,
    public_key: PKey<Public>,
    key_id: Option<String>,
}

impl JwsVerifier for RsassaPssJwsVerifier {
    fn algorithm(&self) -> &dyn JwsAlgorithm {
        &self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn set_key_id(&mut self, key_id: &str) {
        self.key_id = Some(key_id.to_string());
    }

    fn remove_key_id(&mut self) {
        self.key_id = None;
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            let message_digest = match self.algorithm {
                RsassaPssJwsAlgorithm::PS256 => MessageDigest::sha256(),
                RsassaPssJwsAlgorithm::PS384 => MessageDigest::sha384(),
                RsassaPssJwsAlgorithm::PS512 => MessageDigest::sha512(),
            };

            let mut verifier = Verifier::new(message_digest, &self.public_key)?;
            verifier.update(message)?;
            verifier.verify(signature)?;
            Ok(())
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }

    fn box_clone(&self) -> Box<dyn JwsVerifier> {
        Box::new(self.clone())
    }
}

impl Deref for RsassaPssJwsVerifier {
    type Target = dyn JwsVerifier;

    fn deref(&self) -> &Self::Target {
        self
    }
}

impl DerefMut for RsassaPssJwsVerifier {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self
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
    fn sign_and_verify_rsassa_pss_generated_der() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsassaPssJwsAlgorithm::PS256,
            RsassaPssJwsAlgorithm::PS384,
            RsassaPssJwsAlgorithm::PS512,
        ] {
            let keypair = alg.generate_keypair(2048)?;

            let signer = alg.signer_from_der(&keypair.to_der_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_der(&keypair.to_der_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsassa_pss_generated_raw() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsassaPssJwsAlgorithm::PS256,
            RsassaPssJwsAlgorithm::PS384,
            RsassaPssJwsAlgorithm::PS512,
        ] {
            let keypair = alg.generate_keypair(2048)?;

            let signer = alg.signer_from_der(&keypair.to_raw_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_der(&keypair.to_raw_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsassa_pss_generated_pem() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsassaPssJwsAlgorithm::PS256,
            RsassaPssJwsAlgorithm::PS384,
            RsassaPssJwsAlgorithm::PS512,
        ] {
            let keypair = alg.generate_keypair(2048)?;

            let signer = alg.signer_from_pem(&keypair.to_pem_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_pem(&keypair.to_pem_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsassa_pss_generated_traditional_pem() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsassaPssJwsAlgorithm::PS256,
            RsassaPssJwsAlgorithm::PS384,
            RsassaPssJwsAlgorithm::PS512,
        ] {
            let keypair = alg.generate_keypair(2048)?;

            let signer = alg.signer_from_pem(&keypair.to_traditional_pem_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_pem(&keypair.to_pem_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsassa_pss_generated_jwk() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsassaPssJwsAlgorithm::PS256,
            RsassaPssJwsAlgorithm::PS384,
            RsassaPssJwsAlgorithm::PS512,
        ] {
            let keypair = alg.generate_keypair(2048)?;

            let signer = alg.signer_from_jwk(&keypair.to_jwk_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_jwk(&keypair.to_jwk_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsassa_pss_jwt() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsassaPssJwsAlgorithm::PS256,
            RsassaPssJwsAlgorithm::PS384,
            RsassaPssJwsAlgorithm::PS512,
        ] {
            let private_key = load_file("jwk/RSA_private.jwk")?;
            let public_key = load_file("jwk/RSA_public.jwk")?;

            let signer = alg.signer_from_jwk(&Jwk::from_slice(&private_key)?)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_jwk(&Jwk::from_slice(&public_key)?)?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsassa_pss_pkcs8_pem() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsassaPssJwsAlgorithm::PS256,
            RsassaPssJwsAlgorithm::PS384,
            RsassaPssJwsAlgorithm::PS512,
        ] {
            let private_key = load_file(match alg {
                RsassaPssJwsAlgorithm::PS256 => "pem/RSA-PSS_2048bit_SHA-256_private.pem",
                RsassaPssJwsAlgorithm::PS384 => "pem/RSA-PSS_2048bit_SHA-384_private.pem",
                RsassaPssJwsAlgorithm::PS512 => "pem/RSA-PSS_2048bit_SHA-512_private.pem",
            })?;
            let public_key = load_file(match alg {
                RsassaPssJwsAlgorithm::PS256 => "pem/RSA-PSS_2048bit_SHA-256_public.pem",
                RsassaPssJwsAlgorithm::PS384 => "pem/RSA-PSS_2048bit_SHA-384_public.pem",
                RsassaPssJwsAlgorithm::PS512 => "pem/RSA-PSS_2048bit_SHA-512_public.pem",
            })?;

            let signer = alg.signer_from_pem(&private_key)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsassa_pss_pkcs8_der() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsassaPssJwsAlgorithm::PS256,
            RsassaPssJwsAlgorithm::PS384,
            RsassaPssJwsAlgorithm::PS512,
        ] {
            let private_key = load_file(match alg {
                RsassaPssJwsAlgorithm::PS256 => "der/RSA-PSS_2048bit_SHA-256_pkcs8_private.der",
                RsassaPssJwsAlgorithm::PS384 => "der/RSA-PSS_2048bit_SHA-384_pkcs8_private.der",
                RsassaPssJwsAlgorithm::PS512 => "der/RSA-PSS_2048bit_SHA-512_pkcs8_private.der",
            })?;
            let public_key = load_file(match alg {
                RsassaPssJwsAlgorithm::PS256 => "der/RSA-PSS_2048bit_SHA-256_spki_public.der",
                RsassaPssJwsAlgorithm::PS384 => "der/RSA-PSS_2048bit_SHA-384_spki_public.der",
                RsassaPssJwsAlgorithm::PS512 => "der/RSA-PSS_2048bit_SHA-512_spki_public.der",
            })?;

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

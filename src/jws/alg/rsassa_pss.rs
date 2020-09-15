use std::fmt::Display;
use std::ops::Deref;

use anyhow::bail;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use openssl::rsa::Rsa;
use serde_json::Value;

use crate::der::{DerBuilder, DerType};
use crate::jwk::{alg::rsapss::RsaPssKeyPair, alg::rsa::RsaKeyPair, Jwk};
use crate::jws::{JwsAlgorithm, JwsSigner, JwsVerifier};
use crate::util;
use crate::{HashAlgorithm, JoseError};

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
        (|| -> anyhow::Result<RsaPssKeyPair> {
            if bits < 2048 {
                bail!("key length must be 2048 or more.");
            }

            let mut keypair = RsaPssKeyPair::generate(
                bits,
                self.hash_algorithm(),
                self.hash_algorithm(),
                self.salt_len(),
            )?;
            keypair.set_algorithm(Some(self.name()));
            Ok(keypair)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidKeyFormat(err),
        })
    }

    /// Create a RSA-PSS key pair from a private key that is a DER encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey.
    pub fn keypair_from_der(&self, input: impl AsRef<[u8]>) -> Result<RsaPssKeyPair, JoseError> {
        (|| -> anyhow::Result<RsaPssKeyPair> {
            let mut keypair = RsaPssKeyPair::from_der(
                input,
                Some(self.hash_algorithm()),
                Some(self.hash_algorithm()),
                Some(self.salt_len()),
            )?;

            if keypair.key_len() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

            keypair.set_algorithm(Some(self.name()));
            Ok(keypair)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidKeyFormat(err),
        })
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
            let mut keypair = RsaPssKeyPair::from_pem(
                input.as_ref(),
                self.hash_algorithm(),
                self.hash_algorithm(),
                self.salt_len(),
            )?;

            if keypair.key_len() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

            keypair.set_algorithm(Some(self.name()));
            Ok(keypair)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidKeyFormat(err),
        })
    }

    /// Return a signer from a private key that is a DER encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey.
    pub fn signer_from_der(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<RsassaPssJwsSigner, JoseError> {
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
    pub fn signer_from_pem(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<RsassaPssJwsSigner, JoseError> {
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

            let keypair = RsaPssKeyPair::from_jwk(
                jwk,
                self.hash_algorithm(),
                self.hash_algorithm(),
                self.salt_len(),
            )?;
            if keypair.key_len() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

            let private_key = keypair.into_private_key();
            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(RsassaPssJwsSigner {
                algorithm: self.clone(),
                private_key,
                key_id,
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
            let input = input.as_ref();
            let spki_der_vec;
            let spki_der = match RsaPssKeyPair::detect_pkcs8(input, true) {
                Some((hash, mgf1_hash, salt_len)) => {
                    if hash != self.hash_algorithm() {
                        bail!("The message digest parameter is mismatched: {}", hash);
                    } else if mgf1_hash != self.hash_algorithm() {
                        bail!(
                            "The mgf1 message digest parameter is mismatched: {}",
                            mgf1_hash
                        );
                    } else if salt_len != self.salt_len() {
                        bail!("The salt size is mismatched: {}", salt_len);
                    }

                    input.as_ref()
                }
                None => {
                    let rsa_der_vec;
                    let rsa_der = match RsaKeyPair::detect_pkcs8(input, true) {
                        Some(_) => {
                            let rsa = Rsa::public_key_from_der(input)?;
                            rsa_der_vec = rsa.public_key_to_der_pkcs1()?;
                            &rsa_der_vec
                        },
                        None => input
                    };
                    
                    spki_der_vec = RsaPssKeyPair::to_pkcs8(
                        rsa_der, 
                        true,
                        self.hash_algorithm(),
                        self.hash_algorithm(),
                        self.salt_len(),
                    );
                    spki_der_vec.as_slice()
                }
            };

            let public_key = PKey::public_key_from_der(spki_der)?;

            let rsa = public_key.rsa()?;
            if rsa.size() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

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
                "PUBLIC KEY" => match RsaPssKeyPair::detect_pkcs8(&data, true) {
                    Some((hash, mgf1_hash, salt_len)) => {
                        if hash != self.hash_algorithm() {
                            bail!("The message digest parameter is mismatched: {}", hash);
                        } else if mgf1_hash != self.hash_algorithm() {
                            bail!(
                                "The mgf1 message digest parameter is mismatched: {}",
                                mgf1_hash
                            );
                        } else if salt_len != self.salt_len() {
                            bail!("The salt size is mismatched: {}", salt_len);
                        }

                        PKey::public_key_from_der(&data)?
                    }
                    None => bail!("Invalid PEM contents."),
                },
                "RSA PUBLIC KEY" => {
                    let pkcs8 = RsaPssKeyPair::to_pkcs8(
                        &data,
                        true,
                        self.hash_algorithm(),
                        self.hash_algorithm(),
                        self.salt_len(),
                    );
                    PKey::public_key_from_der(&pkcs8)?
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };

            let rsa = public_key.rsa()?;
            if rsa.size() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

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
                self.hash_algorithm(),
                self.hash_algorithm(),
                self.salt_len(),
            );
            let public_key = PKey::public_key_from_der(&pkcs8)?;
            let key_id = jwk.key_id().map(|val| val.to_string());

            let rsa = public_key.rsa()?;
            if rsa.size() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

            Ok(RsassaPssJwsVerifier {
                algorithm: self.clone(),
                public_key,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            Self::PS256 => HashAlgorithm::Sha256,
            Self::PS384 => HashAlgorithm::Sha384,
            Self::PS512 => HashAlgorithm::Sha512,
        }
    }

    fn salt_len(&self) -> u8 {
        match self {
            Self::PS256 => 32,
            Self::PS384 => 48,
            Self::PS512 => 64,
        }
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

impl Display for RsassaPssJwsAlgorithm {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for RsassaPssJwsAlgorithm {
    type Target = dyn JwsAlgorithm;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct RsassaPssJwsSigner {
    algorithm: RsassaPssJwsAlgorithm,
    private_key: PKey<Private>,
    key_id: Option<String>,
}

impl RsassaPssJwsSigner {
    pub fn set_key_id(&mut self, value: impl Into<String>) {
        self.key_id = Some(value.into());
    }

    pub fn remove_key_id(&mut self) {
        self.key_id = None;
    }
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

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let md = self.algorithm.hash_algorithm().message_digest();

            let mut signer = Signer::new(md, &self.private_key)?;
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

#[derive(Debug, Clone)]
pub struct RsassaPssJwsVerifier {
    algorithm: RsassaPssJwsAlgorithm,
    public_key: PKey<Public>,
    key_id: Option<String>,
}

impl RsassaPssJwsVerifier {
    pub fn set_key_id(&mut self, value: impl Into<String>) {
        self.key_id = Some(value.into());
    }

    pub fn remove_key_id(&mut self) {
        self.key_id = None;
    }
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

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            let md = self.algorithm.hash_algorithm().message_digest();

            let mut verifier = Verifier::new(md, &self.public_key)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Result;
    use std::fs;
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
    fn sign_and_verify_rsassa_pss_generated_rsa_der() -> Result<()> {
        let input = b"abcde12345";

        let keypair = RsaKeyPair::generate(2048)?;
        for alg in &[
            RsassaPssJwsAlgorithm::PS256,
            RsassaPssJwsAlgorithm::PS384,
            RsassaPssJwsAlgorithm::PS512,
        ] {
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

            let signer = alg.signer_from_jwk(&Jwk::from_bytes(&private_key)?)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_jwk(&Jwk::from_bytes(&public_key)?)?;
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

        let data = fs::read(&pb)?;
        Ok(data)
    }
}

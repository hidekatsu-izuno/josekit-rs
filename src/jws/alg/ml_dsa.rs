use std::fmt::Display;
use std::ops::Deref;

use anyhow::bail;
#[cfg(feature = "kapun-provider")]
use kapun_crypto_provider::{KeyEncoding, Metadata, Signer, Signing, Verifier, Verifying};

use crate::jwk::alg::ml_dsa::PrivateKey;
use crate::jwk::alg::ml_dsa::{MlDsa, MlDsaKeyPair, PublicKey};
use crate::jwk::{Jwk, PublicKey as PublicKeyTrait};
use crate::jws::{JwsAlgorithm, JwsSigner, JwsVerifier};
use crate::util::{self};
use crate::{JoseError, Value};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum MldsaJwsAlgorithm {
    /// ML-DSA using parameter set 44
    MlDSA44,
    /// ML-DSA using parameter set 65
    MlDSA65,
    /// ML-DSA using parameter set 87
    MlDSA87,
}

impl MldsaJwsAlgorithm {
    /// Generate ML-DSA key pair.
    pub fn generate_key_pair(&self) -> Result<MlDsaKeyPair, JoseError> {
        let mut key_pair = MlDsaKeyPair::generate(self.variant())?;
        key_pair.set_algorithm(Some(self.name()));
        Ok(key_pair)
    }

    /// Create a ML-DSA key pair from a private key that is a DER encoded PKCS#8 PrivateKeyInfo.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo or ECPrivateKey.
    pub fn key_pair_from_der(&self, input: impl AsRef<[u8]>) -> Result<MlDsaKeyPair, JoseError> {
        let mut key_pair = MlDsaKeyPair::from_der(input, Some(self.variant()))?;
        key_pair.set_algorithm(Some(self.name()));
        Ok(key_pair)
    }

    /// Create a Ml-DSA key pair from a private key of common or traditinal PEM format.
    ///
    /// Common PEM format is a DER and base64 encoded PKCS#8 PrivateKeyInfo
    /// that surrounded by "-----BEGIN/END PRIVATE KEY----".
    ///
    /// # Arguments
    /// * `input` - A private key of common or traditinal PEM format.
    pub fn key_pair_from_pem(&self, input: impl AsRef<[u8]>) -> Result<MlDsaKeyPair, JoseError> {
        let mut key_pair = MlDsaKeyPair::from_pem(input.as_ref(), Some(self.variant()))?;
        key_pair.set_algorithm(Some(self.name()));
        Ok(key_pair)
    }

    /// Return a signer from a private key that is a DER encoded PKCS#8 PrivateKeyInfo.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo.
    pub fn signer_from_der(&self, input: impl AsRef<[u8]>) -> Result<MldsaJwsSigner, JoseError> {
        let key_pair = self.key_pair_from_der(input.as_ref())?;
        Ok(MldsaJwsSigner {
            algorithm: self.clone(),
            private_key: key_pair.into_private_key(),
            key_id: None,
        })
    }

    /// Return a signer from a private key of common or traditinal PEM format.
    ///
    /// Common PEM format is a DER and base64 encoded PKCS#8 PrivateKeyInfo
    /// that surrounded by "-----BEGIN/END PRIVATE KEY----".
    ///
    /// Currently, we only support the non expanded version (aka seed)
    ///
    /// # Arguments
    /// * `input` - A private key of common or traditinal PEM format.
    pub fn signer_from_pem(&self, input: impl AsRef<[u8]>) -> Result<MldsaJwsSigner, JoseError> {
        let key_pair = self.key_pair_from_pem(input.as_ref())?;
        Ok(MldsaJwsSigner {
            algorithm: self.clone(),
            private_key: key_pair.into_private_key(),
            key_id: None,
        })
    }

    /// Return a signer from a private key that is formatted by a JWK of EC type.
    ///
    /// # Arguments
    /// * `jwk` - A private key that is formatted by a JWK of EC type.
    pub fn signer_from_jwk(&self, jwk: &Jwk) -> Result<MldsaJwsSigner, JoseError> {
        (|| -> anyhow::Result<MldsaJwsSigner> {
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
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
                None => {}
            }

            let key_pair = MlDsaKeyPair::from_jwk(jwk)?;
            let private_key = key_pair.into_private_key();
            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(MldsaJwsSigner {
                algorithm: self.clone(),
                private_key,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a public key that is a DER encoded SubjectPublicKeyInfo.
    ///
    /// # Arguments
    /// * `input` - A public key that is a DER encoded SubjectPublicKeyInfo.
    pub fn verifier_from_der(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<MldsaJwsVerifier, JoseError> {
        (|| -> anyhow::Result<MldsaJwsVerifier> {
            let public_key = PublicKey::from_der(input.as_ref())?;
            match (self.variant(), &public_key) {
                (MlDsa::MlDsa44, PublicKey::MlDsa44(_)) => (),
                (MlDsa::MlDsa65, PublicKey::MlDsa65(_)) => (),
                (MlDsa::MlDsa87, PublicKey::MlDsa87(_)) => (),
                _ => bail!("format invalid"),
            }
            Ok(MldsaJwsVerifier {
                algorithm: self.clone(),
                public_key,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a key of common PEM format.
    ///
    /// Common PEM format is a DER and base64 encoded SubjectPublicKeyInfo
    /// that surrounded by "-----BEGIN/END PUBLIC KEY----".
    ///
    /// # Arguments
    /// * `input` - A public key of common or traditional PEM format.
    pub fn verifier_from_pem(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<MldsaJwsVerifier, JoseError> {
        (|| -> anyhow::Result<MldsaJwsVerifier> {
            let (alg, data) = util::parse_pem(input.as_ref())?;

            let public_key = match alg.as_str() {
                "PUBLIC KEY" => PublicKey::from_der(data.as_ref())?,
                alg => bail!("Inappropriate algorithm: {}", alg),
            };

            Ok(MldsaJwsVerifier {
                algorithm: self.clone(),
                public_key,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a public key that is formatted by a JWK of EC type.
    ///
    /// # Arguments
    /// * `jwk` - A public key that is formatted by a JWK of EC type.
    pub fn verifier_from_jwk(&self, jwk: &Jwk) -> Result<MldsaJwsVerifier, JoseError> {
        (|| -> anyhow::Result<MldsaJwsVerifier> {
            match jwk.key_type() {
                val if val == "AKP" => {}
                val => bail!("A parameter kty must be EC: {}", val),
            }
            match jwk.key_use() {
                Some(val) if val == "sig" => {}
                None => {}
                Some(val) => bail!("A parameter use must be sig: {}", val),
            }
            if !jwk.is_for_key_operation("verify") {
                bail!("A parameter key_ops must contains verify.");
            }

            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }

            let r#pub = match jwk.parameter("pub") {
                Some(Value::String(val)) => util::decode_base64_urlsafe_no_pad(val)?,
                Some(_) => bail!("A parameter x must be a string."),
                None => bail!("A parameter x is required."),
            };

            let public_key = PublicKey::from_bytes(&r#pub, self.variant())?;
            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(MldsaJwsVerifier {
                algorithm: self.clone(),
                public_key,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn variant(&self) -> MlDsa {
        match self {
            MldsaJwsAlgorithm::MlDSA44 => MlDsa::MlDsa44,
            MldsaJwsAlgorithm::MlDSA65 => MlDsa::MlDsa65,
            MldsaJwsAlgorithm::MlDSA87 => MlDsa::MlDsa87,
        }
    }
}

impl JwsAlgorithm for MldsaJwsAlgorithm {
    fn name(&self) -> &str {
        match self {
            MldsaJwsAlgorithm::MlDSA44 => "ML-DSA-44",
            MldsaJwsAlgorithm::MlDSA65 => "ML-DSA-65",
            MldsaJwsAlgorithm::MlDSA87 => "ML-DSA-87",
        }
    }

    fn box_clone(&self) -> Box<dyn JwsAlgorithm> {
        Box::new(self.clone())
    }
}

impl Display for MldsaJwsAlgorithm {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for MldsaJwsAlgorithm {
    type Target = dyn JwsAlgorithm;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct MldsaJwsSigner {
    algorithm: MldsaJwsAlgorithm,
    private_key: PrivateKey,
    key_id: Option<String>,
}

impl MldsaJwsSigner {
    pub fn set_key_id(&mut self, value: impl Into<String>) {
        self.key_id = Some(value.into());
    }

    pub fn remove_key_id(&mut self) {
        self.key_id = None;
    }
}

impl JwsSigner for MldsaJwsSigner {
    fn algorithm(&self) -> &dyn JwsAlgorithm {
        &self.algorithm
    }

    fn signature_len(&self) -> usize {
        unimplemented!("WHY IS THIS NEEDED");
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> { Ok(self.private_key.sign(message)) })()
            .map_err(|err| JoseError::InvalidSignature(err))
    }

    fn sign_prehashed(&self, digest: &[u8]) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> { Ok(self.private_key.sign_prehash(digest)) })()
            .map_err(|err| JoseError::InvalidSignature(err))
    }

    fn box_clone(&self) -> Box<dyn JwsSigner> {
        Box::new(self.clone())
    }
}

impl Deref for MldsaJwsSigner {
    type Target = dyn JwsSigner;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[cfg(feature = "kapun-provider")]
impl KeyEncoding for MldsaJwsSigner {
    fn kapun_private_pkcs8_der(&self) -> Option<Vec<u8>> {
        self.private_key.to_der_private_key().ok()
    }

    fn kapun_private_pkcs8_pem(&self) -> Option<String> {
        String::from_utf8(self.private_key.to_pem_private_key()).ok()
    }

    fn kapun_public_spki_der(&self) -> Option<Vec<u8>> {
        self.private_key.public_key().to_der().ok()
    }

    fn kapun_public_spki_pem(&self) -> Option<String> {
        self.private_key.public_key().to_pem().ok()
    }
}
#[cfg(feature = "kapun-provider")]
impl KeyEncoding for MldsaJwsVerifier {
    fn kapun_public_spki_der(&self) -> Option<Vec<u8>> {
        self.public_key.to_der().ok()
    }

    fn kapun_public_spki_pem(&self) -> Option<String> {
        self.public_key.to_pem().ok()
    }
}

#[cfg(feature = "kapun-provider")]
impl Signing for MldsaJwsSigner {
    fn kapun_sign(&self, data: Vec<u8>) -> Result<Vec<u8>, kapun_crypto_provider::SigningProblem> {
        self.sign(&data)
            .map_err(|_| kapun_crypto_provider::SigningProblem::SigningFailed)
    }

    fn kapun_sign_hash(
        &self,
        hash: Vec<u8>,
    ) -> Result<Vec<u8>, kapun_crypto_provider::SigningProblem> {
        self.sign_prehashed(&hash)
            .map_err(|_| kapun_crypto_provider::SigningProblem::SigningFailed)
    }
}

#[cfg(feature = "kapun-provider")]
impl Verifying for MldsaJwsVerifier {
    fn kapun_verify(
        &self,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<(), kapun_crypto_provider::VerificationProblem> {
        self.verify(&data, &signature)
            .map_err(|_| kapun_crypto_provider::VerificationProblem::SignatureInvalid)
    }

    fn kapun_verify_hash(
        &self,
        hash: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<(), kapun_crypto_provider::VerificationProblem> {
        self.verify_prehashed(&hash, &signature)
            .map_err(|_| kapun_crypto_provider::VerificationProblem::SignatureInvalid)
    }
}

#[cfg(feature = "kapun-provider")]
impl Metadata for MldsaJwsSigner {
    fn kapun_jose_alg(&self) -> Option<String> {
        Some(self.algorithm.name().to_string())
    }
}
#[cfg(feature = "kapun-provider")]
impl Metadata for MldsaJwsVerifier {
    fn kapun_jose_alg(&self) -> Option<String> {
        Some(self.algorithm.name().to_string())
    }
}

#[derive(Debug, Clone)]
pub struct MldsaJwsVerifier {
    algorithm: MldsaJwsAlgorithm,
    public_key: PublicKey,
    key_id: Option<String>,
}

impl MldsaJwsVerifier {
    pub fn set_key_id(&mut self, value: impl Into<String>) {
        self.key_id = Some(value.into());
    }

    pub fn remove_key_id(&mut self) {
        self.key_id = None;
    }
}

impl PublicKeyTrait for MldsaJwsVerifier {
    fn to_der_public_key(&self) -> Vec<u8> {
        PublicKeyTrait::to_der_public_key(&self.public_key)
    }

    fn to_pem_public_key(&self) -> Vec<u8> {
        PublicKeyTrait::to_pem_public_key(&self.public_key)
    }

    fn to_jwk_public_key(&self) -> Jwk {
        let mut jwk = PublicKeyTrait::to_jwk_public_key(&self.public_key);
        jwk.set_algorithm(self.algorithm.name());
        if let Some(key_id) = &self.key_id {
            jwk.set_key_id(key_id);
        }
        jwk
    }
}

impl JwsVerifier for MldsaJwsVerifier {
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
            if !self
                .public_key
                .verify_signature(&message, &signature)
                .is_ok()
            {
                bail!("The signature does not match.");
            }
            Ok(())
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }

    fn box_clone(&self) -> Box<dyn JwsVerifier> {
        Box::new(self.clone())
    }
}

#[cfg(feature = "kapun-provider")]
impl Signer for MldsaJwsSigner {}
#[cfg(feature = "kapun-provider")]
impl Verifier for MldsaJwsVerifier {}

impl Deref for MldsaJwsVerifier {
    type Target = dyn JwsVerifier;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::jwk::KeyPair;

    use super::*;

    use anyhow::Result;
    use base64::Engine;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn sign_and_verify_mldsa_generated_der() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            MldsaJwsAlgorithm::MlDSA44,
            MldsaJwsAlgorithm::MlDSA65,
            MldsaJwsAlgorithm::MlDSA87,
        ] {
            let key_pair = alg.generate_key_pair()?;

            let signer = alg.signer_from_der(&key_pair.to_der_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_der(&key_pair.to_der_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_mldsa_generated_raw() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            MldsaJwsAlgorithm::MlDSA44,
            MldsaJwsAlgorithm::MlDSA65,
            MldsaJwsAlgorithm::MlDSA87,
        ] {
            let key_pair = alg.generate_key_pair()?;

            let signer = alg.signer_from_der(&key_pair.to_raw_private_key()?)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_der(&key_pair.to_der_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_mldsa_generated_pem() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            MldsaJwsAlgorithm::MlDSA44,
            MldsaJwsAlgorithm::MlDSA65,
            MldsaJwsAlgorithm::MlDSA87,
        ] {
            let key_pair = alg.generate_key_pair()?;

            let signer = alg.signer_from_pem(&key_pair.to_pem_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_pem(&key_pair.to_pem_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_mldsa_generated_traditional_pem() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            MldsaJwsAlgorithm::MlDSA44,
            MldsaJwsAlgorithm::MlDSA65,
            MldsaJwsAlgorithm::MlDSA87,
        ] {
            let key_pair = alg.generate_key_pair()?;

            let signer = alg.signer_from_pem(&key_pair.to_traditional_pem_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_pem(&key_pair.to_pem_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_mldsa_generated_jwk() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            MldsaJwsAlgorithm::MlDSA44,
            MldsaJwsAlgorithm::MlDSA65,
            MldsaJwsAlgorithm::MlDSA87,
        ] {
            let key_pair = alg.generate_key_pair()?;

            let signer = alg.signer_from_jwk(&key_pair.to_jwk_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_jwk(&key_pair.to_jwk_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_mldsa_jwt() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            MldsaJwsAlgorithm::MlDSA44,
            MldsaJwsAlgorithm::MlDSA65,
            MldsaJwsAlgorithm::MlDSA87,
        ] {
            let private_key = load_file(match alg {
                MldsaJwsAlgorithm::MlDSA44 => "jwk/MlDSA44_private.jwk",
                MldsaJwsAlgorithm::MlDSA65 => "jwk/MlDSA65_private.jwk",
                MldsaJwsAlgorithm::MlDSA87 => "jwk/MlDSA87_private.jwk",
            })?;
            let public_key = load_file(match alg {
                MldsaJwsAlgorithm::MlDSA44 => "jwk/MlDSA44_public.jwk",
                MldsaJwsAlgorithm::MlDSA65 => "jwk/MlDSA65_public.jwk",
                MldsaJwsAlgorithm::MlDSA87 => "jwk/MlDSA87_public.jwk",
            })?;

            let signer = alg.signer_from_jwk(&Jwk::from_bytes(&private_key)?)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_jwk(&Jwk::from_bytes(&public_key)?)?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn test_rfc_jws() -> Result<()> {
        for alg in &[
            MldsaJwsAlgorithm::MlDSA44,
            MldsaJwsAlgorithm::MlDSA65,
            MldsaJwsAlgorithm::MlDSA87,
        ] {
            let jws = load_file(match alg {
                MldsaJwsAlgorithm::MlDSA44 => "jwt/MLDSA44.jwt",
                MldsaJwsAlgorithm::MlDSA65 => "jwt/MLDSA65.jwt",
                MldsaJwsAlgorithm::MlDSA87 => "jwt/MLDSA87.jwt",
            })?;
            let public_key = load_file(match alg {
                MldsaJwsAlgorithm::MlDSA44 => "jwk/MlDSA44_public.jwk",
                MldsaJwsAlgorithm::MlDSA65 => "jwk/MlDSA65_public.jwk",
                MldsaJwsAlgorithm::MlDSA87 => "jwk/MlDSA87_public.jwk",
            })?;
            let jws = std::str::from_utf8(jws.as_slice())?;
            let (input, signature) = jws.rsplit_once('.').expect("invalid jwt");
            let signature = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(signature.trim())?;
            let verifier = alg.verifier_from_jwk(&Jwk::from_bytes(&public_key)?)?;
            verifier.verify(input.as_bytes(), &signature)?;
        }
        Ok(())
    }

    #[test]
    fn sign_and_verify_mldsa_pkcs8_pem() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            MldsaJwsAlgorithm::MlDSA44,
            MldsaJwsAlgorithm::MlDSA65,
            MldsaJwsAlgorithm::MlDSA87,
        ] {
            println!("{}", alg);

            let private_key = load_file(match alg {
                MldsaJwsAlgorithm::MlDSA44 => "pem/MlDSA44_private.pem",
                MldsaJwsAlgorithm::MlDSA65 => "pem/MlDSA65_private.pem",
                MldsaJwsAlgorithm::MlDSA87 => "pem/MlDSA87_private.pem",
            })?;
            let public_key = load_file(match alg {
                MldsaJwsAlgorithm::MlDSA44 => "pem/MlDSA44_public.pem",
                MldsaJwsAlgorithm::MlDSA65 => "pem/MlDSA65_public.pem",
                MldsaJwsAlgorithm::MlDSA87 => "pem/MlDSA87_public.pem",
            })?;

            let signer = alg.signer_from_pem(&private_key)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    // #[test]
    // TODO: add pkcs8 der examples
    fn _sign_and_verify_mldsa_pkcs8_der() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            MldsaJwsAlgorithm::MlDSA44,
            MldsaJwsAlgorithm::MlDSA65,
            MldsaJwsAlgorithm::MlDSA87,
        ] {
            let private_key = load_file(match alg {
                MldsaJwsAlgorithm::MlDSA44 => "der/MlDSA44_pkcs8_private.der",
                MldsaJwsAlgorithm::MlDSA65 => "der/MlDSA65_pkcs8_private.der",
                MldsaJwsAlgorithm::MlDSA87 => "der/MlDSA87_pkcs8_private.der",
            })?;
            let public_key = load_file(match alg {
                MldsaJwsAlgorithm::MlDSA44 => "der/MlDSA44_pkcs8_public.der",
                MldsaJwsAlgorithm::MlDSA65 => "der/MlDSA65_pkcs8_public.der",
                MldsaJwsAlgorithm::MlDSA87 => "der/MlDSA87_pkcs8_public.der",
            })?;

            let signer = alg.signer_from_der(&private_key)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_der(&public_key)?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_mldsa_mismatch() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            MldsaJwsAlgorithm::MlDSA44,
            MldsaJwsAlgorithm::MlDSA65,
            MldsaJwsAlgorithm::MlDSA87,
        ] {
            let signer_key_pair = alg.generate_key_pair()?;
            let verifier_key_pair = alg.generate_key_pair()?;

            let signer = alg.signer_from_der(&signer_key_pair.to_der_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_der(&verifier_key_pair.to_der_public_key())?;
            verifier
                .verify(input, &signature)
                .expect_err("Unmatched signature did not fail");
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

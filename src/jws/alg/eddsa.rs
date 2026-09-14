use std::fmt::Display;
use std::ops::Deref;

use anyhow::bail;
#[cfg(feature = "openssl")]
use openssl::pkey::{PKey, Private, Public};
#[cfg(feature = "openssl")]
use openssl::sign::{Signer, Verifier};

#[cfg(feature = "rustcrypto")]
use crate::jwe::alg::ecdh_es::{PrivateKey, PublicKey};
use crate::jwk::{
    alg::ed::{EdCurve, EdKeyPair},
    Jwk, PublicKey as PublicKeyTrait,
};
use crate::jws::{JwsAlgorithm, JwsSigner, JwsVerifier};
use crate::util;
#[cfg(feature = "kapun-provider")]
use crate::{kapun_signing_provider, kapun_verifying_provider};
use crate::{JoseError, Value};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum EddsaJwsAlgorithm {
    /// EdDSA signature algorithms
    Eddsa,
}

impl EddsaJwsAlgorithm {
    /// Generate a EdDSA key pair
    ///
    /// # Arguments
    /// * `curve` - EdDSA curve algorithm
    pub fn generate_key_pair(&self, curve: EdCurve) -> Result<EdKeyPair, JoseError> {
        let mut key_pair = EdKeyPair::generate(curve)?;
        key_pair.set_algorithm(Some(self.name()));
        Ok(key_pair)
    }

    /// Create a EdDSA key pair from a private key that is a DER encoded PKCS#8 PrivateKeyInfo.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo.
    pub fn key_pair_from_der(&self, input: impl AsRef<[u8]>) -> Result<EdKeyPair, JoseError> {
        let mut key_pair = EdKeyPair::from_der(input)?;
        key_pair.set_algorithm(Some(self.name()));
        Ok(key_pair)
    }

    /// Create a EdDSA key pair from a private key of common or traditinal PEM format.
    ///
    /// Common PEM format is a DER and base64 encoded PKCS#8 PrivateKeyInfo
    /// that surrounded by "-----BEGIN/END PRIVATE KEY----".
    ///
    /// Traditional PEM format is a DER and base64 encoded PKCS#8 PrivateKeyInfo
    /// that surrounded by "-----BEGIN/END ED25519/ED448 PRIVATE KEY----".
    ///
    /// # Arguments
    /// * `input` - A private key of common or traditinal PEM format.
    pub fn key_pair_from_pem(&self, input: impl AsRef<[u8]>) -> Result<EdKeyPair, JoseError> {
        let mut key_pair = EdKeyPair::from_pem(input.as_ref())?;
        key_pair.set_algorithm(Some(self.name()));
        Ok(key_pair)
    }

    /// Return a signer from a private key that is a DER encoded PKCS#8 PrivateKeyInfo.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo.
    pub fn signer_from_der(&self, input: impl AsRef<[u8]>) -> Result<EddsaJwsSigner, JoseError> {
        let key_pair = self.key_pair_from_der(input.as_ref())?;
        Ok(EddsaJwsSigner {
            algorithm: self.clone(),
            curve: key_pair.curve(),
            private_key: key_pair.into_private_key(),
            key_id: None,
        })
    }

    /// Return a signer from a private key of common or traditinal PEM format.
    ///
    /// Common PEM format is a DER and base64 encoded PKCS#8 PrivateKeyInfo
    /// that surrounded by "-----BEGIN/END PRIVATE KEY----".
    ///
    /// Traditional PEM format is a DER and base64 encoded PKCS#8 PrivateKeyInfo
    /// that surrounded by "-----BEGIN/END ED25519/ED448 PRIVATE KEY----".
    ///
    /// # Arguments
    /// * `input` - A private key of common or traditinal PEM format.
    pub fn signer_from_pem(&self, input: impl AsRef<[u8]>) -> Result<EddsaJwsSigner, JoseError> {
        let key_pair = self.key_pair_from_pem(input.as_ref())?;
        Ok(EddsaJwsSigner {
            algorithm: self.clone(),
            curve: key_pair.curve(),
            private_key: key_pair.into_private_key(),
            key_id: None,
        })
    }

    /// Return a signer from a private key that is formatted by a JWK of OKP type.
    ///
    /// # Arguments
    /// * `jwk` - A private key that is formatted by a JWK of OKP type.
    pub fn signer_from_jwk(&self, jwk: &Jwk) -> Result<EddsaJwsSigner, JoseError> {
        (|| -> anyhow::Result<EddsaJwsSigner> {
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

            let key_pair = EdKeyPair::from_jwk(jwk)?;
            let curve = key_pair.curve();
            let private_key = key_pair.into_private_key();
            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(EddsaJwsSigner {
                algorithm: self.clone(),
                curve,
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
    ) -> Result<EddsaJwsVerifier, JoseError> {
        (|| -> anyhow::Result<EddsaJwsVerifier> {
            #[allow(unused)]
            let (spki_der, curve) = match EdKeyPair::detect_pkcs8(input.as_ref(), true) {
                Some(curve) => (input.as_ref(), curve),
                None => bail!("The EdDSA public key must be wrapped by PKCS#8 format."),
            };

            #[cfg(feature = "openssl")]
            let public_key = PKey::public_key_from_der(spki_der)?;
            #[cfg(feature = "rustcrypto")]
            let public_key = PublicKey::from_pkcs8_der_with_ed_curve(curve, spki_der)?;

            Ok(EddsaJwsVerifier {
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
    /// * `input` - A key of common or traditional PEM format.
    pub fn verifier_from_pem(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<EddsaJwsVerifier, JoseError> {
        (|| -> anyhow::Result<EddsaJwsVerifier> {
            let (alg, data) = util::parse_pem(input.as_ref())?;
            #[allow(unused)]
            let (spki_der, curve) = match alg.as_str() {
                "PUBLIC KEY" => match EdKeyPair::detect_pkcs8(&data, true) {
                    Some(curve) => (data.as_slice(), curve),
                    None => bail!(
                        "The EdDSA public key must be wrapped by SubjectPublicKeyInfo format."
                    ),
                },
                alg => bail!("Unacceptable algorithm: {}", alg),
            };

            #[cfg(feature = "openssl")]
            let public_key = PKey::public_key_from_der(spki_der)?;
            #[cfg(feature = "rustcrypto")]
            let public_key = PublicKey::from_pkcs8_der_with_ed_curve(curve, spki_der)?;
            Ok(EddsaJwsVerifier {
                algorithm: self.clone(),
                public_key,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a public key that is formatted by a JWK of OKP type.
    ///
    /// # Arguments
    /// * `jwk` - A public key that is formatted by a JWK of OKP type.
    pub fn verifier_from_jwk(&self, jwk: &Jwk) -> Result<EddsaJwsVerifier, JoseError> {
        (|| -> anyhow::Result<EddsaJwsVerifier> {
            match jwk.key_type() {
                val if val == "OKP" => {}
                val => bail!("A parameter kty must be OKP: {}", val),
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
            let curve = match jwk.parameter("crv") {
                Some(Value::String(val)) if val == "Ed25519" => EdCurve::Ed25519,
                Some(Value::String(val)) if val == "Ed448" => EdCurve::Ed448,
                Some(Value::String(val)) => bail!("A parameter crv must is invalid: {}", val),
                Some(_) => bail!("A parameter crv must be a string."),
                None => bail!("A parameter crv is required."),
            };
            let x = match jwk.parameter("x") {
                Some(Value::String(val)) => util::decode_base64_urlsafe_no_pad(val)?,
                Some(_) => bail!("A parameter x must be a string."),
                None => bail!("A parameter x is required."),
            };

            let pkcs8 = EdKeyPair::to_pkcs8(&x, true, curve);
            #[cfg(feature = "openssl")]
            let public_key = PKey::public_key_from_der(&pkcs8)?;
            #[cfg(feature = "rustcrypto")]
            let public_key = PublicKey::from_pkcs8_der_with_ed_curve(curve, &pkcs8)?;
            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(EddsaJwsVerifier {
                algorithm: self.clone(),
                public_key,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }
}

impl JwsAlgorithm for EddsaJwsAlgorithm {
    fn name(&self) -> &str {
        "EdDSA"
    }

    fn box_clone(&self) -> Box<dyn JwsAlgorithm> {
        Box::new(self.clone())
    }
}

impl Display for EddsaJwsAlgorithm {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for EddsaJwsAlgorithm {
    type Target = dyn JwsAlgorithm;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct EddsaJwsSigner {
    algorithm: EddsaJwsAlgorithm,
    curve: EdCurve,
    #[cfg(feature = "openssl")]
    private_key: PKey<Private>,
    #[cfg(feature = "rustcrypto")]
    private_key: PrivateKey,
    key_id: Option<String>,
}

impl EddsaJwsSigner {
    pub fn set_key_id(&mut self, value: impl Into<String>) {
        self.key_id = Some(value.into());
    }

    pub fn remove_key_id(&mut self) {
        self.key_id = None;
    }
}

impl JwsSigner for EddsaJwsSigner {
    fn algorithm(&self) -> &dyn JwsAlgorithm {
        &self.algorithm
    }

    fn signature_len(&self) -> usize {
        match self.curve {
            EdCurve::Ed25519 => 64,
            EdCurve::Ed448 => 114,
        }
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            #[cfg(feature = "openssl")]
            let mut signer = Signer::new_without_digest(&self.private_key)?;
            #[cfg(feature = "openssl")]
            let mut signature = vec![0; signer.len()?];
            #[cfg(feature = "openssl")]
            signer.sign_oneshot(&mut signature, message)?;
            #[cfg(feature = "rustcrypto")]
            let signature = self.private_key.sign(&message)?;
            Ok(signature)
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }

    #[cfg(feature = "rustcrypto")]
    fn sign_prehashed(&self, digest: &[u8]) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let signature = self.private_key.sign_prehashed(&digest)?;
            Ok(signature)
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }

    fn box_clone(&self) -> Box<dyn JwsSigner> {
        Box::new(self.clone())
    }
}

impl Deref for EddsaJwsSigner {
    type Target = dyn JwsSigner;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct EddsaJwsVerifier {
    algorithm: EddsaJwsAlgorithm,
    #[cfg(feature = "openssl")]
    public_key: PKey<Public>,
    #[cfg(feature = "rustcrypto")]
    public_key: PublicKey,
    key_id: Option<String>,
}

impl EddsaJwsVerifier {
    pub fn set_key_id(&mut self, value: impl Into<String>) {
        self.key_id = Some(value.into());
    }

    pub fn remove_key_id(&mut self) {
        self.key_id = None;
    }
}

impl PublicKeyTrait for EddsaJwsVerifier {
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

impl JwsVerifier for EddsaJwsVerifier {
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
            #[cfg(feature = "openssl")]
            let mut verifier = Verifier::new_without_digest(&self.public_key)?;
            #[cfg(feature = "openssl")]
            if !verifier.verify_oneshot(signature, message)? {
                bail!("The signature does not match.")
            }
            #[cfg(feature = "rustcrypto")]
            if self
                .public_key
                .verify_signature(message, signature)
                .is_err()
            {
                bail!("The signature does not match.")
            }
            Ok(())
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }
    #[cfg(feature = "rustcrypto")]
    fn verify_prehashed(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            if self
                .public_key
                .verify_signature(message, signature)
                .is_err()
            {
                bail!("The signature does not match.")
            }
            Ok(())
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }

    fn box_clone(&self) -> Box<dyn JwsVerifier> {
        Box::new(self.clone())
    }
}

impl Deref for EddsaJwsVerifier {
    type Target = dyn JwsVerifier;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[cfg(feature = "kapun-provider")]
kapun_verifying_provider!(EddsaJwsVerifier);
#[cfg(feature = "kapun-provider")]
kapun_signing_provider!(EddsaJwsSigner);

#[cfg(test)]
mod tests {
    use crate::jws::alg::eddsa::EddsaJwsAlgorithm::Eddsa;

    use super::*;

    use anyhow::Result;
    use sha2::{Digest, Sha512};
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn sign_and_verify_eddsa_generated_der() -> Result<()> {
        let input = b"abcde12345";

        for curve in vec![EdCurve::Ed25519, EdCurve::Ed448] {
            println!("--> {curve:?}");
            let alg = EddsaJwsAlgorithm::Eddsa;
            let key_pair = alg.generate_key_pair(curve)?;

            let signer = alg.signer_from_der(&key_pair.to_der_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_der(&key_pair.to_der_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_eddsa_generated_pem() -> Result<()> {
        let input = b"abcde12345";

        for curve in vec![EdCurve::Ed25519, EdCurve::Ed448] {
            let alg = EddsaJwsAlgorithm::Eddsa;
            let key_pair = alg.generate_key_pair(curve)?;

            let signer = alg.signer_from_pem(&key_pair.to_pem_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_pem(&key_pair.to_pem_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_eddsa_generated_traditional_pem() -> Result<()> {
        let input = b"abcde12345";

        for curve in vec![EdCurve::Ed25519, EdCurve::Ed448] {
            let alg = EddsaJwsAlgorithm::Eddsa;
            let key_pair = alg.generate_key_pair(curve)?;

            let signer = alg.signer_from_pem(&key_pair.to_traditional_pem_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_pem(&key_pair.to_pem_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_eddsa_generated_jwk() -> Result<()> {
        let input = b"abcde12345";

        for curve in vec![EdCurve::Ed25519, EdCurve::Ed448] {
            let alg = EddsaJwsAlgorithm::Eddsa;
            let key_pair = alg.generate_key_pair(curve)?;

            let signer = alg.signer_from_jwk(&key_pair.to_jwk_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_jwk(&key_pair.to_jwk_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_eddsa_jwt() -> Result<()> {
        let input = b"abcde12345";

        let alg = EddsaJwsAlgorithm::Eddsa;

        let private_key = load_file("jwk/OKP_Ed25519_private.jwk")?;
        let public_key = load_file("jwk/OKP_Ed25519_private.jwk")?;

        let signer = alg.signer_from_jwk(&Jwk::from_bytes(&private_key)?)?;
        let signature = signer.sign(input)?;

        let verifier = alg.verifier_from_jwk(&Jwk::from_bytes(&public_key)?)?;
        verifier.verify(input, &signature)?;

        Ok(())
    }

    #[test]
    fn sign_and_verify_eddsa_pkcs8_pem() -> Result<()> {
        let input = b"abcde12345";

        let alg = EddsaJwsAlgorithm::Eddsa;

        for crv in &["ED25519", "ED448"] {
            let private_key = load_file(&format!("pem/{}_private.pem", crv))?;
            let public_key = load_file(&format!("pem/{}_public.pem", crv))?;

            let signer = alg.signer_from_pem(&private_key)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_eddsa_pkcs8_der() -> Result<()> {
        let input = b"abcde12345";

        let alg = EddsaJwsAlgorithm::Eddsa;

        for crv in &["ED25519", "ED448"] {
            let private_key = load_file(&format!("der/{}_pkcs8_private.der", crv))?;
            let public_key = load_file(&format!("der/{}_spki_public.der", crv))?;

            let signer = alg.signer_from_der(&private_key)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_der(&public_key)?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_eddsa_mismatch() -> Result<()> {
        let input = b"abcde12345";

        for curve in vec![EdCurve::Ed25519, EdCurve::Ed448] {
            let alg = EddsaJwsAlgorithm::Eddsa;
            let signer_key_pair = alg.generate_key_pair(curve)?;
            let verifier_key_pair = alg.generate_key_pair(curve)?;

            let signer = alg.signer_from_der(&signer_key_pair.to_der_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_der(&verifier_key_pair.to_der_public_key())?;
            verifier
                .verify(input, &signature)
                .expect_err("Unmatched signature did not fail");
        }

        Ok(())
    }
    #[test]
    fn test_sign_prehashed_eddsa() {
        let Value::Object(secret_key) = serde_json::json!({
            "kty":"OKP",
            "crv":"Ed25519",
            "d":"gz_mJAkje51i7HdYdSCRHpp1nOwdGXVbfakBuW3KPUI"
        }) else {
            panic!("")
        };
        let sk = Eddsa
            .signer_from_jwk(&Jwk::from_map(secret_key).unwrap())
            .unwrap();
        let digest = Sha512::digest("test").to_vec();
        let prehashed_sig = sk.sign_prehashed(&digest).unwrap();
        let normal_sig = sk.sign(b"test").unwrap();
        sk.private_key
            .public_key()
            .verify_signature(b"test", &normal_sig)
            .expect("normal failed");
        sk.private_key
            .public_key()
            .verify_signature_prehashed(b"test", &prehashed_sig)
            .expect("prehashed failed");
    }

    fn load_file(path: &str) -> Result<Vec<u8>> {
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push("data");
        pb.push(path);

        let data = fs::read(&pb)?;
        Ok(data)
    }
}

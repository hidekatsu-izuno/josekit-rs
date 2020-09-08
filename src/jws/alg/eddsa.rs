use std::fmt::Display;
use std::ops::Deref;

use anyhow::bail;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use serde_json::Value;

use crate::jose::JoseError;
use crate::jwk::{EdCurve, EdKeyPair, Jwk};
use crate::jws::{JwsAlgorithm, JwsSigner, JwsVerifier};
use crate::util;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum EddsaJwsAlgorithm {
    /// EdDSA signature algorithms
    EdDSA,
}

impl EddsaJwsAlgorithm {
    /// Generate a EdDSA keypair
    ///
    /// # Arguments
    /// * `curve` - EdDSA curve algorithm
    pub fn generate_keypair(&self, curve: EdCurve) -> Result<EdKeyPair, JoseError> {
        let mut keypair = EdKeyPair::generate(curve)?;
        keypair.set_algorithm(Some(self.name()));
        Ok(keypair)
    }

    /// Create a EdDSA key pair from a private key that is a DER encoded PKCS#8 PrivateKeyInfo.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo.
    pub fn keypair_from_der(&self, input: impl AsRef<[u8]>) -> Result<EdKeyPair, JoseError> {
        let mut keypair = EdKeyPair::from_der(input, None)?;
        keypair.set_algorithm(Some(self.name()));
        Ok(keypair)
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
    pub fn keypair_from_pem(&self, input: impl AsRef<[u8]>) -> Result<EdKeyPair, JoseError> {
        let mut keypair = EdKeyPair::from_pem(input.as_ref(), None)?;
        keypair.set_algorithm(Some(self.name()));
        Ok(keypair)
    }

    /// Return a signer from a private key that is a DER encoded PKCS#8 PrivateKeyInfo.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo.
    pub fn signer_from_der(&self, input: impl AsRef<[u8]>) -> Result<EddsaJwsSigner, JoseError> {
        let keypair = self.keypair_from_der(input.as_ref())?;
        Ok(EddsaJwsSigner {
            algorithm: self.clone(),
            curve: keypair.curve(),
            private_key: keypair.into_private_key(),
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
        let keypair = self.keypair_from_pem(input.as_ref())?;
        Ok(EddsaJwsSigner {
            algorithm: self.clone(),
            curve: keypair.curve(),
            private_key: keypair.into_private_key(),
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

            let keypair = EdKeyPair::from_jwk(jwk, None)?;
            let curve = keypair.curve();
            let private_key = keypair.into_private_key();
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
            let spki_der = match EdKeyPair::detect_pkcs8(input.as_ref(), true) {
                Some(_) => input.as_ref(),
                None => bail!("The EdDSA public key must be wrapped by PKCS#8 format."),
            };

            let public_key = PKey::public_key_from_der(spki_der)?;

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
            let spki_der = match alg.as_str() {
                "PUBLIC KEY" => match EdKeyPair::detect_pkcs8(&data, true) {
                    Some(_) => data.as_slice(),
                    None => bail!(
                        "The EdDSA public key must be wrapped by SubjectPublicKeyInfo format."
                    ),
                },
                alg => bail!("Unacceptable algorithm: {}", alg),
            };

            let public_key = PKey::public_key_from_der(spki_der)?;

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
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter x must be a string."),
                None => bail!("A parameter x is required."),
            };

            let pkcs8 = EdKeyPair::to_pkcs8(&x, true, curve);
            let public_key = PKey::public_key_from_der(&pkcs8)?;
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
    private_key: PKey<Private>,
    key_id: Option<String>,
}

impl EddsaJwsSigner {
    pub fn set_key_id(&mut self, key_id: Option<impl Into<String>>) {
        match key_id {
            Some(val) => {
                self.key_id = Some(val.into());
            }
            None => {
                self.key_id = None;
            }
        }
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
            let mut signer = Signer::new_without_digest(&self.private_key)?;
            let mut signature = vec![0; signer.len()?];
            signer.sign_oneshot(&mut signature, message)?;
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
    public_key: PKey<Public>,
    key_id: Option<String>,
}

impl EddsaJwsVerifier {
    pub fn set_key_id(&mut self, key_id: Option<impl Into<String>>) {
        match key_id {
            Some(val) => {
                self.key_id = Some(val.into());
            }
            None => {
                self.key_id = None;
            }
        }
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
            let mut verifier = Verifier::new_without_digest(&self.public_key)?;
            verifier.verify_oneshot(signature, message)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Result;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;

    #[test]
    fn sign_and_verify_eddsa_generated_der() -> Result<()> {
        let input = b"abcde12345";

        for curve in vec![EdCurve::Ed25519, EdCurve::Ed448] {
            let alg = EddsaJwsAlgorithm::EdDSA;
            let keypair = alg.generate_keypair(curve)?;

            let signer = alg.signer_from_der(&keypair.to_der_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_der(&keypair.to_der_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_eddsa_generated_pem() -> Result<()> {
        let input = b"abcde12345";

        for curve in vec![EdCurve::Ed25519, EdCurve::Ed448] {
            let alg = EddsaJwsAlgorithm::EdDSA;
            let keypair = alg.generate_keypair(curve)?;

            let signer = alg.signer_from_pem(&keypair.to_pem_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_pem(&keypair.to_pem_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_eddsa_generated_traditional_pem() -> Result<()> {
        let input = b"abcde12345";

        for curve in vec![EdCurve::Ed25519, EdCurve::Ed448] {
            let alg = EddsaJwsAlgorithm::EdDSA;
            let keypair = alg.generate_keypair(curve)?;

            let signer = alg.signer_from_pem(&keypair.to_traditional_pem_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_pem(&keypair.to_pem_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_eddsa_generated_jwk() -> Result<()> {
        let input = b"abcde12345";

        for curve in vec![EdCurve::Ed25519, EdCurve::Ed448] {
            let alg = EddsaJwsAlgorithm::EdDSA;
            let keypair = alg.generate_keypair(curve)?;

            let signer = alg.signer_from_jwk(&keypair.to_jwk_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_jwk(&keypair.to_jwk_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_eddsa_jwt() -> Result<()> {
        let input = b"abcde12345";

        let alg = EddsaJwsAlgorithm::EdDSA;

        let private_key = load_file("jwk/OKP_Ed25519_private.jwk")?;
        let public_key = load_file("jwk/OKP_Ed25519_private.jwk")?;

        let signer = alg.signer_from_jwk(&Jwk::from_slice(&private_key)?)?;
        let signature = signer.sign(input)?;

        let verifier = alg.verifier_from_jwk(&Jwk::from_slice(&public_key)?)?;
        verifier.verify(input, &signature)?;

        Ok(())
    }

    #[test]
    fn sign_and_verify_eddsa_pkcs8_pem() -> Result<()> {
        let input = b"abcde12345";

        let alg = EddsaJwsAlgorithm::EdDSA;

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

        let alg = EddsaJwsAlgorithm::EdDSA;

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

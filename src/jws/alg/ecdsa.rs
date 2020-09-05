use std::fmt::Display;
use std::ops::Deref;

use anyhow::bail;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use serde_json::Value;

use crate::der::{DerBuilder, DerReader, DerType};
use crate::jose::JoseError;
use crate::jwk::{EcCurve, EcKeyPair, Jwk, KeyPair};
use crate::jws::{JwsAlgorithm, JwsSigner, JwsVerifier};
use crate::util::{self, HashAlgorithm};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum EcdsaJwsAlgorithm {
    /// ECDSA using P-256 and SHA-256
    ES256,
    /// ECDSA using P-384 and SHA-384
    ES384,
    /// ECDSA using P-521 and SHA-512
    ES512,
    /// ECDSA using secp256k1 curve and SHA-256
    ES256K,
}

impl EcdsaJwsAlgorithm {
    /// Generate ECDSA key pair.
    pub fn generate_keypair(&self) -> Result<EcKeyPair, JoseError> {
        let mut keypair = EcKeyPair::generate(self.curve())?;
        keypair.set_algorithm(Some(self.name()));
        Ok(keypair)
    }

    /// Create a EcDSA key pair from a private key that is a DER encoded PKCS#8 PrivateKeyInfo or ECPrivateKey.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo or ECPrivateKey.
    pub fn keypair_from_der(&self, input: impl AsRef<[u8]>) -> Result<EcKeyPair, JoseError> {
        let mut keypair = EcKeyPair::from_der(input, Some(self.curve()))?;
        keypair.set_algorithm(Some(self.name()));
        Ok(keypair)
    }

    /// Create a EcDSA key pair from a private key of common or traditinal PEM format.
    ///
    /// Common PEM format is a DER and base64 encoded PKCS#8 PrivateKeyInfo
    /// that surrounded by "-----BEGIN/END PRIVATE KEY----".
    ///
    /// Traditional PEM format is a DER and base64 encoded ECPrivateKey
    /// that surrounded by "-----BEGIN/END EC PRIVATE KEY----".
    ///
    /// # Arguments
    /// * `input` - A private key of common or traditinal PEM format.
    pub fn keypair_from_pem(&self, input: impl AsRef<[u8]>) -> Result<EcKeyPair, JoseError> {
        let mut keypair = EcKeyPair::from_pem(input.as_ref(), Some(self.curve()))?;
        keypair.set_algorithm(Some(self.name()));
        Ok(keypair)
    }

    /// Return a signer from a private key that is a DER encoded PKCS#8 PrivateKeyInfo or ECPrivateKey.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo or ECPrivateKey.
    pub fn signer_from_der(&self, input: impl AsRef<[u8]>) -> Result<EcdsaJwsSigner, JoseError> {
        let keypair = self.keypair_from_der(input.as_ref())?;
        Ok(EcdsaJwsSigner {
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
    /// Traditional PEM format is a DER and base64 encoded ECPrivateKey
    /// that surrounded by "-----BEGIN/END EC PRIVATE KEY----".
    ///
    /// # Arguments
    /// * `input` - A private key of common or traditinal PEM format.
    pub fn signer_from_pem(&self, input: impl AsRef<[u8]>) -> Result<EcdsaJwsSigner, JoseError> {
        let keypair = self.keypair_from_pem(input.as_ref())?;
        Ok(EcdsaJwsSigner {
            algorithm: self.clone(),
            private_key: keypair.into_private_key(),
            key_id: None,
        })
    }

    /// Return a signer from a private key that is formatted by a JWK of EC type.
    ///
    /// # Arguments
    /// * `jwk` - A private key that is formatted by a JWK of EC type.
    pub fn signer_from_jwk(&self, jwk: &Jwk) -> Result<EcdsaJwsSigner, JoseError> {
        (|| -> anyhow::Result<EcdsaJwsSigner> {
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
            
            let keypair = EcKeyPair::from_jwk(jwk, Some(self.curve()))?;
            let private_key = keypair.into_private_key();
            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(EcdsaJwsSigner {
                algorithm: self.clone(),
                private_key,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a public key that is a DER encoded SubjectPublicKeyInfo or ECPoint.
    ///
    /// # Arguments
    /// * `input` - A public key that is a DER encoded SubjectPublicKeyInfo or ECPoint.
    pub fn verifier_from_der(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<EcdsaJwsVerifier, JoseError> {
        (|| -> anyhow::Result<EcdsaJwsVerifier> {
            let pkcs8;
            let pkcs8_ref = match EcKeyPair::detect_pkcs8(input.as_ref(), true) {
                Some(curve) if curve == self.curve() => input.as_ref(),
                Some(curve) => bail!("The curve is mismatched: {}", curve),
                None => {
                    pkcs8 = EcKeyPair::to_pkcs8(input.as_ref(), true, self.curve());
                    &pkcs8
                }
            };

            let public_key = PKey::public_key_from_der(pkcs8_ref)?;

            Ok(EcdsaJwsVerifier {
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
    /// Traditional PEM format is a DER and base64 ECParameters
    /// that surrounded by "-----BEGIN/END EC PUBLIC KEY----".
    ///
    /// # Arguments
    /// * `input` - A public key of common or traditional PEM format.
    pub fn verifier_from_pem(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<EcdsaJwsVerifier, JoseError> {
        (|| -> anyhow::Result<EcdsaJwsVerifier> {
            let (alg, data) = util::parse_pem(input.as_ref())?;

            let pkcs8;
            let pkcs8_ref = match alg.as_str() {
                "PUBLIC KEY" => {
                    if let None = EcKeyPair::detect_pkcs8(&data, true) {
                        bail!("PEM contents is expected PKCS#8 wrapped key.");
                    }
                    &data
                }
                "EC PUBLIC KEY" => {
                    pkcs8 = EcKeyPair::to_pkcs8(&data, true, self.curve());
                    &pkcs8
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };

            let public_key = PKey::public_key_from_der(pkcs8_ref)?;

            Ok(EcdsaJwsVerifier {
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
    pub fn verifier_from_jwk(&self, jwk: &Jwk) -> Result<EcdsaJwsVerifier, JoseError> {
        (|| -> anyhow::Result<EcdsaJwsVerifier> {
            let curve = self.curve();

            match jwk.key_type() {
                val if val == "EC" => {}
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
            match jwk.parameter("crv") {
                Some(Value::String(val)) if val == curve.name() => {}
                Some(Value::String(val)) => {
                    bail!("A parameter crv must be {} but {}", curve.name(), val)
                }
                Some(_) => bail!("A parameter crv must be a string."),
                None => bail!("A parameter crv is required."),
            }
            let x = match jwk.parameter("x") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter x must be a string."),
                None => bail!("A parameter x is required."),
            };
            let y = match jwk.parameter("y") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter y must be a string."),
                None => bail!("A parameter y is required."),
            };

            let mut vec = Vec::with_capacity(1 + x.len() + y.len());
            vec.push(0x04);
            vec.extend_from_slice(&x);
            vec.extend_from_slice(&y);

            let pkcs8 = EcKeyPair::to_pkcs8(&vec, true, self.curve());
            let public_key = PKey::public_key_from_der(&pkcs8)?;
            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(EcdsaJwsVerifier {
                algorithm: self.clone(),
                public_key,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn curve(&self) -> EcCurve {
        match self {
            Self::ES256 => EcCurve::P256,
            Self::ES384 => EcCurve::P384,
            Self::ES512 => EcCurve::P521,
            Self::ES256K => EcCurve::Secp256K1,
        }
    }
    
    fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            Self::ES256 => HashAlgorithm::Sha256,
            Self::ES384 => HashAlgorithm::Sha384,
            Self::ES512 => HashAlgorithm::Sha512,
            Self::ES256K => HashAlgorithm::Sha256,
        }
    }
}

impl JwsAlgorithm for EcdsaJwsAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
            Self::ES512 => "ES512",
            Self::ES256K => "ES256K",
        }
    }

    fn box_clone(&self) -> Box<dyn JwsAlgorithm> {
        Box::new(self.clone())
    }
}

impl Display for EcdsaJwsAlgorithm {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for EcdsaJwsAlgorithm {
    type Target = dyn JwsAlgorithm;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct EcdsaJwsSigner {
    algorithm: EcdsaJwsAlgorithm,
    private_key: PKey<Private>,
    key_id: Option<String>,
}

impl EcdsaJwsSigner {
    pub fn set_key_id(&mut self, key_id: Option<impl Into<String>>) {
        match key_id {
            Some(val) => {
                self.key_id = Some(val.into());
            },
            None => {
                self.key_id = None;
            }
        }
    }
}

impl JwsSigner for EcdsaJwsSigner {
    fn algorithm(&self) -> &dyn JwsAlgorithm {
        &self.algorithm
    }

    fn signature_len(&self) -> usize {
        match self.algorithm {
            EcdsaJwsAlgorithm::ES256 => 64,
            EcdsaJwsAlgorithm::ES384 => 96,
            EcdsaJwsAlgorithm::ES512 => 131,
            EcdsaJwsAlgorithm::ES256K => 64,
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
            let md = self.algorithm.hash_algorithm().message_digest();

            let mut signer = Signer::new(md, &self.private_key)?;
            signer.update(message)?;
            let signature = signer.sign_to_vec()?;

            let mut der_signature = Vec::with_capacity(6 + 32 + 32);
            let mut reader = DerReader::from_bytes(&signature);
            match reader.next()? {
                Some(DerType::Sequence) => {}
                _ => unreachable!("A generated signature is invalid."),
            }
            match reader.next()? {
                Some(DerType::Integer) => {
                    der_signature.extend_from_slice(&reader.to_be_bytes(false));
                }
                _ => unreachable!("A generated signature is invalid."),
            }
            match reader.next()? {
                Some(DerType::Integer) => {
                    der_signature.extend_from_slice(&reader.to_be_bytes(false));
                }
                _ => unreachable!("A generated signature is invalid."),
            }
            Ok(der_signature)
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }

    fn box_clone(&self) -> Box<dyn JwsSigner> {
        Box::new(self.clone())
    }
}

impl Deref for EcdsaJwsSigner {
    type Target = dyn JwsSigner;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct EcdsaJwsVerifier {
    algorithm: EcdsaJwsAlgorithm,
    public_key: PKey<Public>,
    key_id: Option<String>,
}

impl EcdsaJwsVerifier {
    pub fn set_key_id(&mut self, key_id: Option<impl Into<String>>) {
        match key_id {
            Some(val) => {
                self.key_id = Some(val.into());
            },
            None => {
                self.key_id = None;
            }
        }
    }
}

impl JwsVerifier for EcdsaJwsVerifier {
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
            let mut der_builder = DerBuilder::new(); // 6 + 33 + 33
            der_builder.begin(DerType::Sequence);
            {
                der_builder.append_integer_from_be_slice(&signature[..32], false);
                der_builder.append_integer_from_be_slice(&signature[32..], false);
            }
            der_builder.end();
            let der_signature = der_builder.build();

            let md = self.algorithm.hash_algorithm().message_digest();

            let mut verifier = Verifier::new(md, &self.public_key)?;
            verifier.update(message)?;
            verifier.verify(&der_signature)?;
            Ok(())
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }

    fn box_clone(&self) -> Box<dyn JwsVerifier> {
        Box::new(self.clone())
    }
}

impl Deref for EcdsaJwsVerifier {
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
    fn sign_and_verify_ecdsa_generated_der() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            EcdsaJwsAlgorithm::ES256,
            EcdsaJwsAlgorithm::ES384,
            EcdsaJwsAlgorithm::ES512,
            EcdsaJwsAlgorithm::ES256K,
        ] {
            let keypair = alg.generate_keypair()?;

            let signer = alg.signer_from_der(&keypair.to_der_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_der(&keypair.to_der_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_ecdsa_generated_raw() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            EcdsaJwsAlgorithm::ES256,
            EcdsaJwsAlgorithm::ES384,
            EcdsaJwsAlgorithm::ES512,
            EcdsaJwsAlgorithm::ES256K,
        ] {
            let keypair = alg.generate_keypair()?;

            let signer = alg.signer_from_der(&keypair.to_raw_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_der(&keypair.to_der_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_ecdsa_generated_pem() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            EcdsaJwsAlgorithm::ES256,
            EcdsaJwsAlgorithm::ES384,
            EcdsaJwsAlgorithm::ES512,
            EcdsaJwsAlgorithm::ES256K,
        ] {
            let keypair = alg.generate_keypair()?;

            let signer = alg.signer_from_pem(&keypair.to_pem_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_pem(&keypair.to_pem_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_ecdsa_generated_traditional_pem() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            EcdsaJwsAlgorithm::ES256,
            EcdsaJwsAlgorithm::ES384,
            EcdsaJwsAlgorithm::ES512,
            EcdsaJwsAlgorithm::ES256K,
        ] {
            let keypair = alg.generate_keypair()?;

            let signer = alg.signer_from_pem(&keypair.to_traditional_pem_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_pem(&keypair.to_pem_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_ecdsa_generated_jwk() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            EcdsaJwsAlgorithm::ES256,
            EcdsaJwsAlgorithm::ES384,
            EcdsaJwsAlgorithm::ES512,
            EcdsaJwsAlgorithm::ES256K,
        ] {
            let keypair = alg.generate_keypair()?;

            let signer = alg.signer_from_jwk(&keypair.to_jwk_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_jwk(&keypair.to_jwk_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_ecdsa_jwt() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            EcdsaJwsAlgorithm::ES256,
            EcdsaJwsAlgorithm::ES384,
            EcdsaJwsAlgorithm::ES512,
            EcdsaJwsAlgorithm::ES256K,
        ] {
            let private_key = load_file(match alg {
                EcdsaJwsAlgorithm::ES256 => "jwk/EC_P-256_private.jwk",
                EcdsaJwsAlgorithm::ES384 => "jwk/EC_P-384_private.jwk",
                EcdsaJwsAlgorithm::ES512 => "jwk/EC_P-521_private.jwk",
                EcdsaJwsAlgorithm::ES256K => "jwk/EC_secp256k1_private.jwk",
            })?;
            let public_key = load_file(match alg {
                EcdsaJwsAlgorithm::ES256 => "jwk/EC_P-256_public.jwk",
                EcdsaJwsAlgorithm::ES384 => "jwk/EC_P-384_public.jwk",
                EcdsaJwsAlgorithm::ES512 => "jwk/EC_P-521_public.jwk",
                EcdsaJwsAlgorithm::ES256K => "jwk/EC_secp256k1_public.jwk",
            })?;

            let signer = alg.signer_from_jwk(&Jwk::from_slice(&private_key)?)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_jwk(&Jwk::from_slice(&public_key)?)?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_ecdsa_pkcs8_pem() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            EcdsaJwsAlgorithm::ES256,
            EcdsaJwsAlgorithm::ES384,
            EcdsaJwsAlgorithm::ES512,
            EcdsaJwsAlgorithm::ES256K,
        ] {
            let private_key = load_file(match alg {
                EcdsaJwsAlgorithm::ES256 => "pem/EC_P-256_private.pem",
                EcdsaJwsAlgorithm::ES384 => "pem/EC_P-384_private.pem",
                EcdsaJwsAlgorithm::ES512 => "pem/EC_P-521_private.pem",
                EcdsaJwsAlgorithm::ES256K => "pem/EC_secp256k1_private.pem",
            })?;
            let public_key = load_file(match alg {
                EcdsaJwsAlgorithm::ES256 => "pem/EC_P-256_public.pem",
                EcdsaJwsAlgorithm::ES384 => "pem/EC_P-384_public.pem",
                EcdsaJwsAlgorithm::ES512 => "pem/EC_P-521_public.pem",
                EcdsaJwsAlgorithm::ES256K => "pem/EC_secp256k1_public.pem",
            })?;

            let signer = alg.signer_from_pem(&private_key)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_ecdsa_pkcs8_der() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            EcdsaJwsAlgorithm::ES256,
            EcdsaJwsAlgorithm::ES384,
            EcdsaJwsAlgorithm::ES512,
            EcdsaJwsAlgorithm::ES256K,
        ] {
            let private_key = load_file(match alg {
                EcdsaJwsAlgorithm::ES256 => "der/EC_P-256_pkcs8_private.der",
                EcdsaJwsAlgorithm::ES384 => "der/EC_P-384_pkcs8_private.der",
                EcdsaJwsAlgorithm::ES512 => "der/EC_P-521_pkcs8_private.der",
                EcdsaJwsAlgorithm::ES256K => "der/EC_secp256k1_pkcs8_private.der",
            })?;
            let public_key = load_file(match alg {
                EcdsaJwsAlgorithm::ES256 => "der/EC_P-256_spki_public.der",
                EcdsaJwsAlgorithm::ES384 => "der/EC_P-384_spki_public.der",
                EcdsaJwsAlgorithm::ES512 => "der/EC_P-521_spki_public.der",
                EcdsaJwsAlgorithm::ES256K => "der/EC_secp256k1_spki_public.der",
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

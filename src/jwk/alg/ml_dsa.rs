use std::fmt::Display;

use ::ml_dsa::{KeyExport, Keypair, MlDsa44, MlDsa65, MlDsa87};
use anyhow::{anyhow, bail, Context};
use der::oid::db::fips204::{ID_ML_DSA_44, ID_ML_DSA_65, ID_ML_DSA_87};
use ml_dsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
use ml_dsa::{KeyInit, Seed, SignatureEncoding};
use ml_dsa::{Signer, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::digest::Update;
use signature::DigestSigner;

use crate::JoseError;
use crate::{
    jwk::{Jwk, KeyPair, PublicKey as PublicKeyTrait},
    util::{
        self,
        oid::{ObjectIdentifier, ML_DSA_44, ML_DSA_65, ML_DSA_87},
    },
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MlDsa {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl MlDsa {
    pub fn name(&self) -> &str {
        match self {
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }

    pub fn oid(&self) -> &ObjectIdentifier {
        match self {
            MlDsa::MlDsa44 => &*ML_DSA_44,
            MlDsa::MlDsa65 => &*ML_DSA_65,
            MlDsa::MlDsa87 => &*ML_DSA_87,
        }
    }
}

impl Display for MlDsa {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

#[derive(Debug, Clone)]
pub enum PrivateKey {
    MlDsa44(::ml_dsa::SigningKey<MlDsa44>),
    MlDsa65(::ml_dsa::SigningKey<MlDsa65>),
    MlDsa87(::ml_dsa::SigningKey<MlDsa87>),
}

impl PrivateKey {
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            PrivateKey::MlDsa44(signing_key) => signing_key.sign(msg).to_vec(),
            PrivateKey::MlDsa65(signing_key) => signing_key.sign(msg).to_vec(),
            PrivateKey::MlDsa87(signing_key) => signing_key.sign(msg).to_vec(),
        }
    }
    pub fn sign_prehash(&self, digest: &[u8]) -> Vec<u8> {
        match self {
            PrivateKey::MlDsa44(signing_key) => {
                signing_key.sign_digest(|d| d.update(digest)).to_vec()
            }
            PrivateKey::MlDsa65(signing_key) => {
                signing_key.sign_digest(|d| d.update(digest)).to_vec()
            }
            PrivateKey::MlDsa87(signing_key) => {
                signing_key.sign_digest(|d| d.update(digest)).to_vec()
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum PublicKey {
    MlDsa44(::ml_dsa::VerifyingKey<MlDsa44>),
    MlDsa65(::ml_dsa::VerifyingKey<MlDsa65>),
    MlDsa87(::ml_dsa::VerifyingKey<MlDsa87>),
}

impl PublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PublicKey::MlDsa44(verifying_key) => verifying_key.to_bytes().to_vec(),
            PublicKey::MlDsa65(verifying_key) => verifying_key.to_bytes().to_vec(),
            PublicKey::MlDsa87(verifying_key) => verifying_key.to_bytes().to_vec(),
        }
    }
    pub fn to_der(&self) -> Result<Vec<u8>, anyhow::Error> {
        Ok(match self {
            PublicKey::MlDsa44(verifying_key) => verifying_key
                .to_public_key_der()
                .context("Failed to decode der")?
                .to_vec(),
            PublicKey::MlDsa65(verifying_key) => verifying_key
                .to_public_key_der()
                .context("Failed to decode der")?
                .to_vec(),
            PublicKey::MlDsa87(verifying_key) => verifying_key
                .to_public_key_der()
                .context("Failed to decode der")?
                .to_vec(),
        })
    }
    pub fn to_pem(&self) -> Result<String, anyhow::Error> {
        Ok(match self {
            PublicKey::MlDsa44(verifying_key) => verifying_key
                .to_public_key_pem(base64ct::LineEnding::CRLF)
                .context("failed to encode as a pem")?,

            PublicKey::MlDsa65(verifying_key) => verifying_key
                .to_public_key_pem(base64ct::LineEnding::CRLF)
                .context("failed to encode as a pem")?,
            PublicKey::MlDsa87(verifying_key) => verifying_key
                .to_public_key_pem(base64ct::LineEnding::CRLF)
                .context("failed to encode as a pem")?,
        })
    }
    pub fn from_der(der: &[u8]) -> Result<Self, JoseError> {
        use ml_dsa::pkcs8::DecodePublicKey;
        let public_key = match ml_dsa::pkcs8::SubjectPublicKeyInfoRef::try_from(der) {
            Ok(spki) => match spki.algorithm.oid {
                ID_ML_DSA_44 => {
                    PublicKey::MlDsa44(VerifyingKey::from_public_key_der(der).map_err(|err| {
                        JoseError::InvalidKeyFormat(anyhow!("Failed to decode key: {err}"))
                    })?)
                }
                ID_ML_DSA_65 => {
                    PublicKey::MlDsa65(VerifyingKey::from_public_key_der(der).map_err(|err| {
                        JoseError::InvalidKeyFormat(anyhow!("Failed to decode key: {err}"))
                    })?)
                }
                ID_ML_DSA_87 => {
                    PublicKey::MlDsa87(VerifyingKey::from_public_key_der(der).map_err(|err| {
                        JoseError::InvalidKeyFormat(anyhow!("Failed to decode key: {err}"))
                    })?)
                }
                _ => return Err(JoseError::InvalidKeyFormat(anyhow::anyhow!("Invalid oid"))),
            },
            Err(e) => {
                return Err(JoseError::InvalidKeyFormat(anyhow::anyhow!(
                    "Failed to decode {e}"
                )))
            }
        };
        Ok(public_key)
    }
    pub fn from_bytes(pub_key: &[u8], variant: MlDsa) -> Result<Self, anyhow::Error> {
        Ok(match variant {
            MlDsa::MlDsa44 => PublicKey::MlDsa44(
                ml_dsa::VerifyingKey::new_from_slice(pub_key)
                    .context("Failed to derive public key")?,
            ),
            MlDsa::MlDsa65 => PublicKey::MlDsa65(
                ml_dsa::VerifyingKey::new_from_slice(pub_key)
                    .context("Failed to derive public key")?,
            ),
            MlDsa::MlDsa87 => PublicKey::MlDsa87(
                ml_dsa::VerifyingKey::new_from_slice(pub_key)
                    .context("Failed to derive public key")?,
            ),
        })
    }
    pub fn verify_signature(&self, msg: &[u8], signature: &[u8]) -> Result<(), anyhow::Error> {
        match self {
            PublicKey::MlDsa44(verifying_key) => verifying_key
                .verify(
                    msg,
                    &ml_dsa::Signature::try_from(signature)
                        .context("Failed to deserialize signature")?,
                )
                .context("Failed to verify signature"),
            PublicKey::MlDsa65(verifying_key) => verifying_key
                .verify(
                    msg,
                    &ml_dsa::Signature::try_from(signature)
                        .context("Failed to deserialize signature")?,
                )
                .context("Failed to verify signature"),
            PublicKey::MlDsa87(verifying_key) => verifying_key
                .verify(
                    msg,
                    &ml_dsa::Signature::try_from(signature)
                        .context("Failed to deserialize signature")?,
                )
                .context("Failed to verify signature"),
        }
    }
}

impl PublicKeyTrait for PublicKey {
    fn to_der_public_key(&self) -> Vec<u8> {
        self.to_der().unwrap_or_default()
    }

    fn to_pem_public_key(&self) -> Vec<u8> {
        self.to_pem().unwrap_or_default().into_bytes()
    }

    fn to_jwk_public_key(&self) -> Jwk {
        let variant = match self {
            PublicKey::MlDsa44(_) => MlDsa::MlDsa44,
            PublicKey::MlDsa65(_) => MlDsa::MlDsa65,
            PublicKey::MlDsa87(_) => MlDsa::MlDsa87,
        };
        let mut jwk = Jwk::new("AKP");
        jwk.set_parameter("alg", Some(Value::String(variant.to_string())))
            .unwrap();
        jwk.set_parameter(
            "pub",
            Some(Value::String(util::encode_base64_urlsafe_nopad(
                self.to_bytes(),
            ))),
        )
        .unwrap();
        jwk
    }
}

impl PrivateKey {
    pub fn public_key(&self) -> PublicKey {
        match self {
            PrivateKey::MlDsa44(signing_key) => PublicKey::MlDsa44(signing_key.verifying_key()),
            PrivateKey::MlDsa65(signing_key) => PublicKey::MlDsa65(signing_key.verifying_key()),
            PrivateKey::MlDsa87(signing_key) => PublicKey::MlDsa87(signing_key.verifying_key()),
        }
    }
    pub fn secret_bytes(&self) -> Vec<u8> {
        match self {
            PrivateKey::MlDsa44(signing_key) => signing_key.to_seed().to_vec(),
            PrivateKey::MlDsa65(signing_key) => signing_key.to_seed().to_vec(),
            PrivateKey::MlDsa87(signing_key) => signing_key.to_seed().to_vec(),
        }
    }
    pub fn to_der_private_key(&self) -> Result<Vec<u8>, anyhow::Error> {
        Ok(match self {
            PrivateKey::MlDsa44(signing_key) => signing_key
                .to_pkcs8_der()
                .context("failed to encode as der")?
                .to_bytes()
                .to_vec(),
            PrivateKey::MlDsa65(signing_key) => signing_key
                .to_pkcs8_der()
                .context("failed to encode as der")?
                .to_bytes()
                .to_vec(),
            PrivateKey::MlDsa87(signing_key) => signing_key
                .to_pkcs8_der()
                .context("failed to encode as der")?
                .to_bytes()
                .to_vec(),
        })
    }

    pub fn to_pem_private_key(&self) -> Vec<u8> {
        match self {
            PrivateKey::MlDsa44(signing_key) => signing_key
                .to_pkcs8_pem(pkcs8::LineEnding::CRLF)
                .unwrap()
                .as_bytes()
                .to_vec(),
            PrivateKey::MlDsa65(signing_key) => signing_key
                .to_pkcs8_pem(pkcs8::LineEnding::CRLF)
                .unwrap()
                .as_bytes()
                .to_vec(),
            PrivateKey::MlDsa87(signing_key) => signing_key
                .to_pkcs8_pem(pkcs8::LineEnding::CRLF)
                .unwrap()
                .as_bytes()
                .to_vec(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MlDsaKeyPair {
    private_key: PrivateKey,
    variant: MlDsa,
    algorithm: Option<String>,
    key_id: Option<String>,
}

impl MlDsaKeyPair {
    pub fn variant(&self) -> MlDsa {
        self.variant
    }

    pub fn set_algorithm(&mut self, value: Option<&str>) {
        self.algorithm = value.map(|val| val.to_string());
    }

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

    pub(crate) fn into_private_key(self) -> PrivateKey {
        self.private_key
    }

    /// Generate ML-DSA key pair.
    pub fn generate(variant: MlDsa) -> Result<MlDsaKeyPair, JoseError> {
        (|| -> anyhow::Result<MlDsaKeyPair> {
            use ::ml_dsa::Generate;
            let rng = &mut rand::rng();
            let private_key = match variant {
                MlDsa::MlDsa44 => {
                    PrivateKey::MlDsa44(::ml_dsa::SigningKey::<MlDsa44>::generate_from_rng(rng))
                }
                MlDsa::MlDsa65 => {
                    PrivateKey::MlDsa65(::ml_dsa::SigningKey::<MlDsa65>::generate_from_rng(rng))
                }
                MlDsa::MlDsa87 => {
                    PrivateKey::MlDsa87(::ml_dsa::SigningKey::<MlDsa87>::generate_from_rng(rng))
                }
            };

            Ok(MlDsaKeyPair {
                variant,
                private_key,
                algorithm: None,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Create a EC key pair from a private key that is a DER encoded PKCS#8 PrivateKeyInfo or ECPrivateKey.
    ///
    /// # Arguments
    ///
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo or ECPrivateKey.
    /// * `curve` - EC curve
    pub fn from_der(
        input: impl AsRef<[u8]>,
        specified_variant: Option<MlDsa>,
    ) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let input = input.as_ref();
            let secret_document: ::ml_dsa::pkcs8::SecretDocument =
                ::ml_dsa::pkcs8::SecretDocument::try_from(input).unwrap();
            let private_key_info: ml_dsa::pkcs8::PrivateKeyInfoRef =
                secret_document.decode_msg().expect("failed");

            let (variant, private_key) = match private_key_info.algorithm.oid {
                ID_ML_DSA_44 => (
                    MlDsa::MlDsa44,
                    PrivateKey::MlDsa44(private_key_info.try_into().map_err(|e| {
                        JoseError::InvalidKeyFormat(anyhow::anyhow!("Invalid length: {e}"))
                    })?),
                ),
                ID_ML_DSA_65 => (
                    MlDsa::MlDsa65,
                    PrivateKey::MlDsa65(private_key_info.try_into().map_err(|e| {
                        JoseError::InvalidKeyFormat(anyhow::anyhow!("Invalid length: {e}"))
                    })?),
                ),
                ID_ML_DSA_87 => (
                    MlDsa::MlDsa87,
                    PrivateKey::MlDsa87(private_key_info.try_into().map_err(|e| {
                        JoseError::InvalidKeyFormat(anyhow::anyhow!("Invalid length: {e}"))
                    })?),
                ),
                _ => bail!("PEM contents is expected PKCS#8 wrapped key."),
            };
            if let Some(specified_variant) = specified_variant {
                if variant != specified_variant {
                    bail!("Invalid variant");
                }
            }

            Ok(MlDsaKeyPair {
                private_key,
                variant,
                algorithm: None,
                key_id: None,
            })
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidKeyFormat(err),
        })
    }

    /// Return a signer from a private key that is formatted by a JWK of AKP type.
    ///
    /// # Arguments
    ///
    /// * `jwk` - A private key that is formatted by a JWK of AKP type.
    pub fn from_jwk(jwk: &Jwk) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            match jwk.key_type() {
                val if val == "AKP" => {}
                val => bail!("A parameter kty must be AKP: {}", val),
            }
            let r#priv = match jwk.parameter("priv") {
                Some(Value::String(val)) => {
                    Seed::try_from(&util::decode_base64_urlsafe_no_pad(val)?)?
                }
                Some(_) => bail!("A parameter priv must be a string."),
                None => bail!("A parameter priv is required."),
            };

            let (variant, private_key) = match jwk.parameter("alg") {
                Some(Value::String(val)) => match val.as_str() {
                    "ML-DSA-44" => (
                        MlDsa::MlDsa44,
                        PrivateKey::MlDsa44(::ml_dsa::SigningKey::from_seed(&r#priv)),
                    ),
                    "ML-DSA-65" => (
                        MlDsa::MlDsa65,
                        PrivateKey::MlDsa65(::ml_dsa::SigningKey::from_seed(&r#priv)),
                    ),
                    "ML-DSA-87" => (
                        MlDsa::MlDsa87,
                        PrivateKey::MlDsa87(::ml_dsa::SigningKey::from_seed(&r#priv)),
                    ),

                    _ => bail!("A Unknown variant: {}", val),
                },
                Some(_) => bail!("A parameter crv must be a string."),
                None => bail!("A parameter crv is required."),
            };

            let algorithm = jwk.algorithm().map(|val| val.to_string());
            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(MlDsaKeyPair {
                private_key,
                variant,
                algorithm,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Create a AKP key pair from a private key of common or traditinal PEM format.
    ///
    /// Common PEM format is a DER and base64 encoded PKCS#8 PrivateKeyInfo
    /// that surrounded by "-----BEGIN/END PRIVATE KEY----".
    ///
    /// # Arguments
    ///
    /// * `input` - A private key of common or traditinal PEM format.
    /// * `variant` - ML-DSA variant
    pub fn from_pem(input: impl AsRef<[u8]>, curve: Option<MlDsa>) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let (alg, data) = util::parse_pem(input.as_ref())?;

            let (variant, private_key) = match alg.as_str() {
                "PRIVATE KEY" => {
                    let private_key_info: ::ml_dsa::pkcs8::PrivateKeyInfoRef =
                        ::ml_dsa::pkcs8::PrivateKeyInfoRef::try_from(data.as_slice()).unwrap();

                    match (private_key_info.algorithm.oid, curve) {
                        (ID_ML_DSA_44, Some(MlDsa::MlDsa44) | None) => (
                            MlDsa::MlDsa44,
                            PrivateKey::MlDsa44(private_key_info.try_into().map_err(|e| {
                                JoseError::InvalidKeyFormat(anyhow::anyhow!("Invalid length: {e}"))
                            })?),
                        ),
                        (ID_ML_DSA_65, Some(MlDsa::MlDsa65) | None) => (
                            MlDsa::MlDsa65,
                            PrivateKey::MlDsa65(private_key_info.try_into().map_err(|e| {
                                JoseError::InvalidKeyFormat(anyhow::anyhow!("Invalid length: {e}"))
                            })?),
                        ),
                        (ID_ML_DSA_87, Some(MlDsa::MlDsa87) | None) => (
                            MlDsa::MlDsa87,
                            PrivateKey::MlDsa87(private_key_info.try_into().map_err(|e| {
                                JoseError::InvalidKeyFormat(anyhow::anyhow!("Invalid length: {e}"))
                            })?),
                        ),
                        _ => bail!("PEM contents is expected PKCS#8 wrapped key."),
                    }
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };

            Ok(MlDsaKeyPair {
                private_key,
                variant,
                algorithm: None,
                key_id: None,
            })
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidKeyFormat(err),
        })
    }

    pub fn to_raw_private_key(&self) -> Result<Vec<u8>, anyhow::Error> {
        self.private_key.to_der_private_key()
    }

    pub fn to_traditional_pem_private_key(&self) -> Vec<u8> {
        self.private_key.to_pem_private_key()
    }

    fn to_jwk(&self, private: bool, public: bool) -> Jwk {
        let mut jwk = Jwk::new("AKP");
        if let Some(val) = &self.algorithm {
            jwk.set_algorithm(val);
        }
        if let Some(val) = &self.key_id {
            jwk.set_key_id(val);
        }
        jwk.set_parameter("alg", Some(Value::String(self.variant().to_string())))
            .unwrap();
        if private {
            let private_part = self.private_key.secret_bytes();
            let private_part = util::encode_base64_urlsafe_nopad(&private_part);

            jwk.set_parameter("priv", Some(Value::String(private_part)))
                .unwrap();
        }
        if public {
            let public_part = self.private_key.public_key().to_bytes();
            let public_part = util::encode_base64_urlsafe_nopad(&public_part);

            jwk.set_parameter("pub", Some(Value::String(public_part)))
                .unwrap();
        }
        jwk
    }
}

impl KeyPair for MlDsaKeyPair {
    fn algorithm(&self) -> Option<&str> {
        match &self.algorithm {
            Some(val) => Some(val.as_str()),
            None => None,
        }
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_str()),
            None => None,
        }
    }
    fn to_der_private_key(&self) -> Vec<u8> {
        self.private_key.to_der_private_key().unwrap_or_default()
    }

    fn to_der_public_key(&self) -> Vec<u8> {
        self.private_key.public_key().to_der().unwrap_or_default()
    }

    fn to_pem_private_key(&self) -> Vec<u8> {
        self.private_key.to_pem_private_key()
    }

    fn to_pem_public_key(&self) -> Vec<u8> {
        self.private_key
            .public_key()
            .to_pem()
            .unwrap_or_default()
            .as_bytes()
            .to_vec()
    }

    fn to_jwk_private_key(&self) -> Jwk {
        self.to_jwk(true, false)
    }

    fn to_jwk_public_key(&self) -> Jwk {
        self.to_jwk(false, true)
    }

    fn to_jwk_key_pair(&self) -> Jwk {
        self.to_jwk(true, true)
    }

    fn box_clone(&self) -> Box<dyn KeyPair> {
        Box::new(self.clone())
    }
}

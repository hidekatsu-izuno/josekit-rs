use std::collections::BTreeSet;
use std::fmt::Display;
use std::iter::Iterator;

use anyhow::bail;
use once_cell::sync::Lazy;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use serde_json::Value;

use crate::der::oid::ObjectIdentifier;
use crate::der::{DerBuilder, DerReader, DerType};
use crate::error::JoseError;
use crate::jwk::{Jwk, KeyPair};
use crate::jws::{JwsAlgorithm, JwsSigner, JwsVerifier};
use crate::util::parse_pem;

static OID_ED25519: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 101, 112]));

static OID_ED448: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 101, 113]));

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum EddsaCurve {
    ED25519,
    ED448,
}

impl EddsaCurve {
    pub fn name(&self) -> &str {
        match self {
            Self::ED25519 => "Ed25519",
            Self::ED448 => "Ed448",
        }
    }

    fn oid(&self) -> &ObjectIdentifier {
        match self {
            Self::ED25519 => &*OID_ED25519,
            Self::ED448 => &*OID_ED448,
        }
    }
}

impl Display for EddsaCurve {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum EddsaJwsAlgorithm {
    /// EdDSA signature algorithms
    EDDSA,
}

impl EddsaJwsAlgorithm {
    /// Generate a EdDSA keypair
    ///
    /// # Arguments
    /// * `curve` - EdDSA curve algorithm
    pub fn generate_keypair(&self, curve: &EddsaCurve) -> Result<EddsaKeyPair, JoseError> {
        (|| -> anyhow::Result<EddsaKeyPair> {
            let pkey = match curve {
                EddsaCurve::ED25519 => PKey::generate_ed25519()?,
                EddsaCurve::ED448 => PKey::generate_ed448()?,
            };

            Ok(EddsaKeyPair {
                algorithm: self.clone(),
                curve: curve.clone(),
                pkey,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Create a EdDSA key pair from a private key that is a DER encoded PKCS#8 PrivateKeyInfo.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo.
    pub fn keypair_from_der(&self, input: impl AsRef<[u8]>) -> Result<EddsaKeyPair, JoseError> {
        (|| -> anyhow::Result<EddsaKeyPair> {
            let result = self.detect_pkcs8(input.as_ref(), false)?;
            let (curve, pkey) = if let Some(curve) = result {
                let pkey = PKey::private_key_from_der(input.as_ref())?;
                (curve, pkey)
            } else {
                bail!("The EdDSA private key must be wrapped by PKCS#8 format.");
            };

            Ok(EddsaKeyPair {
                algorithm: self.clone(),
                curve,
                pkey,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
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
    pub fn keypair_from_pem(&self, input: impl AsRef<[u8]>) -> Result<EddsaKeyPair, JoseError> {
        (|| -> anyhow::Result<EddsaKeyPair> {
            let (alg, data) = parse_pem(input.as_ref())?;
            let (curve, pkey) = match alg.as_str() {
                "PRIVATE KEY" => {
                    if let Some(curve) = self.detect_pkcs8(&data, false)? {
                        let pkey = PKey::private_key_from_der(&data)?;
                        (curve, pkey)
                    } else {
                        bail!("The EdDSA private key must be wrapped by PKCS#8 format.");
                    }
                }
                "ED25519 PRIVATE KEY" => {
                    if let Some(curve) = self.detect_pkcs8(&data, false)? {
                        if curve == EddsaCurve::ED25519 {
                            let pkey = PKey::private_key_from_der(&data)?;
                            (curve, pkey)
                        } else {
                            bail!("The EdDSA curve is mismatched: {}", curve.name());
                        }
                    } else {
                        bail!("The EdDSA private key must be wrapped by PKCS#8 format.");
                    }
                }
                "ED448 PRIVATE KEY" => {
                    if let Some(curve) = self.detect_pkcs8(&data, false)? {
                        if curve == EddsaCurve::ED448 {
                            let pkey = PKey::private_key_from_der(&data)?;
                            (curve, pkey)
                        } else {
                            bail!("The EdDSA curve is mismatched: {}", curve.name());
                        }
                    } else {
                        bail!("The EdDSA private key must be wrapped by PKCS#8 format.");
                    }
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };

            Ok(EddsaKeyPair {
                algorithm: self.clone(),
                curve,
                pkey,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a signer from a private key that is a DER encoded PKCS#8 PrivateKeyInfo.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo.
    pub fn signer_from_der(&self, input: impl AsRef<[u8]>) -> Result<EddsaJwsSigner, JoseError> {
        let keypair = self.keypair_from_der(input.as_ref())?;
        Ok(EddsaJwsSigner {
            algorithm: keypair.algorithm,
            private_key: keypair.pkey,
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
            algorithm: keypair.algorithm,
            private_key: keypair.pkey,
            key_id: None,
        })
    }

    /// Return a signer from a private key that is formatted by a JWK of OKP type.
    ///
    /// # Arguments
    /// * `jwk` - A private key that is formatted by a JWK of OKP type.
    pub fn signer_from_jwk(&self, jwk: &Jwk) -> Result<EddsaJwsSigner, JoseError> {
        (|| -> anyhow::Result<EddsaJwsSigner> {
            match jwk.key_type() {
                val if val == self.key_type() => {}
                val => bail!("A parameter kty must be {}: {}", self.key_type(), val),
            }
            match jwk.key_use() {
                Some(val) if val == "sig" => {}
                None => {}
                Some(val) => bail!("A parameter use must be sig: {}", val),
            }
            match jwk.key_operations() {
                Some(vals) if vals.iter().any(|e| e == "sign") => {}
                None => {}
                _ => bail!("A parameter key_ops must contains sign."),
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }
            let key_id = jwk.key_id();

            let curve = match jwk.parameter("crv") {
                Some(Value::String(val)) if val == "Ed25519" => &OID_ED25519,
                Some(Value::String(val)) if val == "Ed448" => &OID_ED448,
                Some(Value::String(val)) => bail!("A parameter crv is invalid: {}", val),
                Some(_) => bail!("A parameter crv must be a string."),
                None => bail!("A parameter crv is required."),
            };
            let d = match jwk.parameter("d") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter d must be a string."),
                None => bail!("A parameter d is required."),
            };

            let mut builder = DerBuilder::new();
            builder.append_octed_string_from_slice(&d);

            let pkcs8 = self.to_pkcs8(&builder.build(), false, curve);
            let pkey = PKey::private_key_from_der(&pkcs8)?;

            Ok(EddsaJwsSigner {
                algorithm: self.clone(),
                private_key: pkey,
                key_id: key_id.map(|val| val.to_string()),
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
            let pkey = if let Some(_) = self.detect_pkcs8(input.as_ref(), true)? {
                PKey::public_key_from_der(input.as_ref())?
            } else {
                bail!("The EdDSA public key must be wrapped by PKCS#8 format.");
            };

            Ok(EddsaJwsVerifier::new(self, pkey, None))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a key of common or traditional PEM format.
    ///
    /// Common PEM format is a DER and base64 encoded SubjectPublicKeyInfo
    /// that surrounded by "-----BEGIN/END PUBLIC KEY----".
    ///
    /// Traditional PEM format is a DER and base64 SubjectPublicKeyInfo
    /// that surrounded by "-----BEGIN/END ED25519/ED448 PUBLIC KEY----".
    ///
    /// # Arguments
    /// * `input` - A key of common or traditional PEM format.
    pub fn verifier_from_pem(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<EddsaJwsVerifier, JoseError> {
        (|| -> anyhow::Result<EddsaJwsVerifier> {
            let (alg, data) = parse_pem(input.as_ref())?;
            let pkey = match alg.as_str() {
                "PUBLIC KEY" => {
                    if let Some(_) = self.detect_pkcs8(&data, true)? {
                        PKey::public_key_from_der(&data)?
                    } else {
                        bail!("The EdDSA public key must be wrapped by PKCS#8 format.");
                    }
                }
                "ED25519 PUBLIC KEY" => {
                    if let Some(curve) = self.detect_pkcs8(&data, true)? {
                        if curve == EddsaCurve::ED25519 {
                            PKey::public_key_from_der(&data)?
                        } else {
                            bail!("The EdDSA curve is mismatched: {}", curve.name());
                        }
                    } else {
                        bail!("The EdDSA public key must be wrapped by PKCS#8 format.");
                    }
                }
                "ED448 PUBLIC KEY" => {
                    if let Some(curve) = self.detect_pkcs8(&data, true)? {
                        if curve == EddsaCurve::ED448 {
                            PKey::public_key_from_der(&data)?
                        } else {
                            bail!("The EdDSA curve is mismatched: {}", curve.name());
                        }
                    } else {
                        bail!("The EdDSA public key must be wrapped by PKCS#8 format.");
                    }
                }
                alg => bail!("Unacceptable algorithm: {}", alg),
            };

            Ok(EddsaJwsVerifier::new(self, pkey, None))
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
                val if val == self.key_type() => {}
                val => bail!("A parameter kty must be {}: {}", self.key_type(), val),
            }
            match jwk.key_use() {
                Some(val) if val == "sig" => {}
                None => {}
                Some(val) => bail!("A parameter use must be sig: {}", val),
            }
            match jwk.key_operations() {
                Some(vals) if vals.iter().any(|e| e == "verify") => {}
                None => {}
                _ => bail!("A parameter key_ops must contains verify."),
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }

            let curve = match jwk.parameter("crv") {
                Some(Value::String(val)) if val == "Ed25519" => &OID_ED25519,
                Some(Value::String(val)) if val == "Ed448" => &OID_ED448,
                Some(Value::String(val)) => bail!("A parameter crv must is invalid: {}", val),
                Some(_) => bail!("A parameter crv must be a string."),
                None => bail!("A parameter crv is required."),
            };
            let x = match jwk.parameter("x") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter x must be a string."),
                None => bail!("A parameter x is required."),
            };

            let pkcs8 = self.to_pkcs8(&x, true, curve);
            let pkey = PKey::public_key_from_der(&pkcs8)?;
            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(EddsaJwsVerifier::new(self, pkey, key_id))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn detect_pkcs8(&self, input: &[u8], is_public: bool) -> anyhow::Result<Option<EddsaCurve>> {
        let curve;
        let mut reader = DerReader::from_reader(input);

        match reader.next() {
            Ok(Some(DerType::Sequence)) => {}
            _ => return Ok(None),
        }

        {
            if !is_public {
                // Version
                match reader.next() {
                    Ok(Some(DerType::Integer)) => match reader.to_u8() {
                        Ok(val) => {
                            if val != 0 {
                                return Ok(None);
                            }
                        }
                        _ => return Ok(None),
                    },
                    _ => return Ok(None),
                }
            }

            match reader.next() {
                Ok(Some(DerType::Sequence)) => {}
                _ => return Ok(None),
            }

            {
                curve = match reader.next() {
                    Ok(Some(DerType::ObjectIdentifier)) => match reader.to_object_identifier() {
                        Ok(val) if val == *OID_ED25519 => EddsaCurve::ED25519,
                        Ok(val) if val == *OID_ED448 => EddsaCurve::ED448,
                        _ => return Ok(None),
                    },
                    _ => return Ok(None),
                }
            }
        }

        Ok(Some(curve))
    }

    fn to_pkcs8(&self, input: &[u8], is_public: bool, crv: &ObjectIdentifier) -> Vec<u8> {
        let mut builder = DerBuilder::new();
        builder.begin(DerType::Sequence);
        {
            if !is_public {
                builder.append_integer_from_u8(0);
            }

            builder.begin(DerType::Sequence);
            {
                builder.append_object_identifier(crv);
            }
            builder.end();

            if is_public {
                builder.append_bit_string_from_slice(input, 0);
            } else {
                builder.append_octed_string_from_slice(input);
            }
        }
        builder.end();

        builder.build()
    }
}

impl JwsAlgorithm for EddsaJwsAlgorithm {
    fn name(&self) -> &str {
        "EdDSA"
    }

    fn key_type(&self) -> &str {
        "OKP"
    }

    fn signature_len(&self) -> usize {
        match self {
            Self::EDDSA => 86,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EddsaKeyPair {
    algorithm: EddsaJwsAlgorithm,
    curve: EddsaCurve,
    pkey: PKey<Private>,
}

impl EddsaKeyPair {
    pub fn to_traditional_pem_private_key(&self) -> Vec<u8> {
        let der = self.pkey.private_key_to_der().unwrap();
        let der = base64::encode_config(&der, base64::STANDARD);
        let alg = match self.curve {
            EddsaCurve::ED25519 => "ED25519 PRIVATE KEY",
            EddsaCurve::ED448 => "ED448 PRIVATE KEY",
        };

        let mut result = String::new();
        result.push_str("-----BEGIN ");
        result.push_str(alg);
        result.push_str("-----\r\n");
        for i in 0..((der.len() + 64 - 1) / 64) {
            result.push_str(&der[(i * 64)..std::cmp::min((i + 1) * 64, der.len())]);
            result.push_str("\r\n");
        }
        result.push_str("-----END ");
        result.push_str(alg);
        result.push_str("-----\r\n");

        result.into_bytes()
    }

    fn to_jwk(&self, private: bool, public: bool) -> Jwk {
        let mut jwk = Jwk::new("OKP");
        jwk.set_key_use("sig");
        jwk.set_key_operations({
            let mut key_ops = Vec::new();
            if private {
                key_ops.push("sign");
            }
            if public {
                key_ops.push("verify");
            }
            key_ops
        });
        jwk.set_algorithm(self.algorithm.name());
        jwk.set_parameter("crv", Some(Value::String(self.curve.name().to_string())))
            .unwrap();

        if private {
            let private_der = self.pkey.private_key_to_der().unwrap();

            let mut reader = DerReader::from_bytes(&private_der);

            match reader.next() {
                Ok(Some(DerType::Sequence)) => {}
                _ => unreachable!("Invalid private key."),
            }

            match reader.next() {
                Ok(Some(DerType::Integer)) => {
                    if reader.to_u8().unwrap() != 0 {
                        unreachable!("Invalid private key.");
                    }
                }
                _ => unreachable!("Invalid private key."),
            }

            match reader.next() {
                Ok(Some(DerType::Sequence)) => {}
                _ => unreachable!("Invalid private key."),
            }

            match reader.next() {
                Ok(Some(DerType::ObjectIdentifier)) => {
                    if &reader.to_object_identifier().unwrap() != self.curve.oid() {
                        unreachable!("Invalid private key.");
                    }
                }
                _ => unreachable!("Invalid private key."),
            }

            match reader.next() {
                Ok(Some(DerType::EndOfContents)) => {}
                _ => unreachable!("Invalid private key."),
            }

            let d = match reader.next() {
                Ok(Some(DerType::OctetString)) => {
                    let private_key = reader.contents().unwrap();
                    let mut reader = DerReader::from_bytes(&private_key);
                    match reader.next() {
                        Ok(Some(DerType::OctetString)) => {
                            let d = reader.contents().unwrap();
                            base64::encode_config(d, base64::URL_SAFE_NO_PAD)
                        }
                        _ => unreachable!("Invalid private key."),
                    }
                }
                _ => unreachable!("Invalid private key."),
            };

            jwk.set_parameter("d", Some(Value::String(d))).unwrap();
        }
        if public {
            let public_der = self.pkey.public_key_to_der().unwrap();
            let mut reader = DerReader::from_bytes(&public_der);

            match reader.next() {
                Ok(Some(DerType::Sequence)) => {}
                _ => unreachable!("Invalid private key."),
            }

            match reader.next() {
                Ok(Some(DerType::Sequence)) => {}
                _ => unreachable!("Invalid private key."),
            }

            match reader.next() {
                Ok(Some(DerType::ObjectIdentifier)) => {
                    if &reader.to_object_identifier().unwrap() != self.curve.oid() {
                        unreachable!("Invalid private key.");
                    }
                }
                _ => unreachable!("Invalid private key."),
            }

            match reader.next() {
                Ok(Some(DerType::EndOfContents)) => {}
                _ => unreachable!("Invalid private key."),
            }

            let x = match reader.next() {
                Ok(Some(DerType::BitString)) => {
                    if let (x, 0) = reader.to_bit_vec().unwrap() {
                        base64::encode_config(x, base64::URL_SAFE_NO_PAD)
                    } else {
                        unreachable!("Invalid private key.")
                    }
                }
                _ => unreachable!("Invalid private key."),
            };

            jwk.set_parameter("x", Some(Value::String(x))).unwrap();
        }

        jwk
    }
}

impl KeyPair for EddsaKeyPair {
    fn to_der_private_key(&self) -> Vec<u8> {
        self.pkey.private_key_to_der().unwrap()
    }

    fn to_der_public_key(&self) -> Vec<u8> {
        self.pkey.public_key_to_der().unwrap()
    }

    fn to_pem_private_key(&self) -> Vec<u8> {
        self.pkey.private_key_to_pem_pkcs8().unwrap()
    }

    fn to_pem_public_key(&self) -> Vec<u8> {
        self.pkey.public_key_to_pem().unwrap()
    }

    fn to_jwk_private_key(&self) -> Jwk {
        self.to_jwk(true, false)
    }

    fn to_jwk_public_key(&self) -> Jwk {
        self.to_jwk(false, true)
    }

    fn to_jwk_keypair(&self) -> Jwk {
        self.to_jwk(true, true)
    }
}

#[derive(Debug, Clone)]
pub struct EddsaJwsSigner {
    algorithm: EddsaJwsAlgorithm,
    private_key: PKey<Private>,
    key_id: Option<String>,
}

impl JwsSigner for EddsaJwsSigner {
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

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let mut signer = Signer::new_without_digest(&self.private_key)?;
            let mut signature = vec![0; signer.len()?];
            signer.sign_oneshot(&mut signature, message)?;
            Ok(signature)
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }
}

#[derive(Debug, Clone)]
pub struct EddsaJwsVerifier {
    algorithm: EddsaJwsAlgorithm,
    public_key: PKey<Public>,
    key_id: Option<String>,
    acceptable_criticals: BTreeSet<String>,
}

impl EddsaJwsVerifier {
    fn new(
        algorithm: &EddsaJwsAlgorithm,
        public_key: PKey<Public>,
        key_id: Option<String>,
    ) -> Self {
        Self {
            algorithm: algorithm.clone(),
            public_key,
            key_id,
            acceptable_criticals: BTreeSet::new(),
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

    fn set_key_id(&mut self, key_id: &str) {
        self.key_id = Some(key_id.to_string());
    }

    fn remove_key_id(&mut self) {
        self.key_id = None;
    }

    fn is_acceptable_critical(&self, name: &str) -> bool {
        self.acceptable_criticals.contains(name)
    }

    fn add_acceptable_critical(&mut self, name: &str) {
        self.acceptable_criticals.insert(name.to_string());
    }

    fn remove_acceptable_critical(&mut self, name: &str) {
        self.acceptable_criticals.remove(name);
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            let mut verifier = Verifier::new_without_digest(&self.public_key)?;
            verifier.verify_oneshot(signature, message)?;
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
    fn sign_and_verify_eddsa_generated_der() -> Result<()> {
        let input = b"abcde12345";

        for curve in &[EddsaCurve::ED25519, EddsaCurve::ED448] {
            let alg = EddsaJwsAlgorithm::EDDSA;
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

        for curve in &[EddsaCurve::ED25519, EddsaCurve::ED448] {
            let alg = EddsaJwsAlgorithm::EDDSA;
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

        for curve in &[EddsaCurve::ED25519, EddsaCurve::ED448] {
            let alg = EddsaJwsAlgorithm::EDDSA;
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

        for curve in &[EddsaCurve::ED25519, EddsaCurve::ED448] {
            let alg = EddsaJwsAlgorithm::EDDSA;
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

        let alg = EddsaJwsAlgorithm::EDDSA;

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

        let alg = EddsaJwsAlgorithm::EDDSA;

        for crv in &["ED25519", "ED448"] {
            let private_key = load_file(&format!("pem/{}_pkcs8_private.pem", crv))?;
            let public_key = load_file(&format!("pem/{}_pkcs8_public.pem", crv))?;

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

        let alg = EddsaJwsAlgorithm::EDDSA;

        for crv in &["ED25519", "ED448"] {
            let private_key = load_file(&format!("der/{}_pkcs8_private.der", crv))?;
            let public_key = load_file(&format!("der/{}_pkcs8_public.der", crv))?;

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

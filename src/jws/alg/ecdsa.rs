use std::iter::Iterator;

use anyhow::bail;
use once_cell::sync::Lazy;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use serde_json::Value;

use crate::der::oid::ObjectIdentifier;
use crate::der::{DerBuilder, DerReader, DerType};
use crate::jose::JoseError;
use crate::jwk::{Jwk, KeyPair};
use crate::jws::{JwsAlgorithm, JwsSigner, JwsVerifier};
use crate::util::{num_to_vec, parse_pem};

static OID_ID_EC_PUBLIC_KEY: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 2, 1]));

static OID_PRIME256V1: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 3, 1, 7]));

static OID_SECP384R1: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 132, 0, 34]));

static OID_SECP521R1: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 132, 0, 35]));

static OID_SECP256K1: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 132, 0, 10]));

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
    pub fn generate_keypair(&self) -> Result<EcdsaKeyPair, JoseError> {
        (|| -> anyhow::Result<EcdsaKeyPair> {
            let ec_group = EcGroup::from_curve_name(match self {
                Self::ES256 => Nid::X9_62_PRIME256V1,
                Self::ES384 => Nid::SECP384R1,
                Self::ES512 => Nid::SECP521R1,
                Self::ES256K => Nid::SECP256K1,
            })?;
            let ec_key = EcKey::generate(&ec_group)?;
            let pkey = PKey::from_ec_key(ec_key)?;

            Ok(EcdsaKeyPair {
                algorithm: self.clone(),
                pkey,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Create a EcDSA key pair from a private key that is a DER encoded PKCS#8 PrivateKeyInfo or ECPrivateKey.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo or ECPrivateKey.
    pub fn keypair_from_der(&self, input: impl AsRef<[u8]>) -> Result<EcdsaKeyPair, JoseError> {
        (|| -> anyhow::Result<EcdsaKeyPair> {
            let pkcs8;
            let pkcs8_ref = if self.detect_pkcs8(input.as_ref(), false)? {
                input.as_ref()
            } else {
                pkcs8 = self.to_pkcs8(input.as_ref(), false);
                &pkcs8
            };

            let pkey = PKey::private_key_from_der(pkcs8_ref)?;

            Ok(EcdsaKeyPair {
                algorithm: self.clone(),
                pkey,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
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
    pub fn keypair_from_pem(&self, input: impl AsRef<[u8]>) -> Result<EcdsaKeyPair, JoseError> {
        (|| -> anyhow::Result<EcdsaKeyPair> {
            let (alg, data) = parse_pem(input.as_ref())?;
            let pkcs8;
            let pkcs8_ref = match alg.as_str() {
                "PRIVATE KEY" => {
                    if !self.detect_pkcs8(&data, false)? {
                        bail!("PEM contents is expected PKCS#8 wrapped key.");
                    }
                    &data
                }
                "EC PRIVATE KEY" => {
                    pkcs8 = self.to_pkcs8(&data, false);
                    &pkcs8
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };

            let pkey = PKey::private_key_from_der(pkcs8_ref)?;

            Ok(EcdsaKeyPair {
                algorithm: self.clone(),
                pkey,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a signer from a private key that is a DER encoded PKCS#8 PrivateKeyInfo or ECPrivateKey.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo or ECPrivateKey.
    pub fn signer_from_der(&self, input: impl AsRef<[u8]>) -> Result<EcdsaJwsSigner, JoseError> {
        let keypair = self.keypair_from_der(input.as_ref())?;
        Ok(EcdsaJwsSigner {
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
    /// Traditional PEM format is a DER and base64 encoded ECPrivateKey
    /// that surrounded by "-----BEGIN/END EC PRIVATE KEY----".
    ///
    /// # Arguments
    /// * `input` - A private key of common or traditinal PEM format.
    pub fn signer_from_pem(&self, input: impl AsRef<[u8]>) -> Result<EcdsaJwsSigner, JoseError> {
        let keypair = self.keypair_from_pem(input.as_ref())?;
        Ok(EcdsaJwsSigner {
            algorithm: keypair.algorithm,
            private_key: keypair.pkey,
            key_id: None,
        })
    }

    /// Return a signer from a private key that is formatted by a JWK of EC type.
    ///
    /// # Arguments
    /// * `jwk` - A private key that is formatted by a JWK of EC type.
    pub fn signer_from_jwk(&self, jwk: &Jwk) -> Result<EcdsaJwsSigner, JoseError> {
        (|| -> anyhow::Result<EcdsaJwsSigner> {
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

            match jwk.parameter("crv") {
                Some(Value::String(val)) if val == self.curve_name() => {}
                Some(Value::String(val)) => {
                    bail!("A parameter crv must be {} but {}", self.curve_name(), val)
                }
                Some(_) => bail!("A parameter crv must be a string."),
                None => bail!("A parameter crv is required."),
            }
            let d = match jwk.parameter("d") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter d must be a string."),
                None => bail!("A parameter d is required."),
            };

            let mut builder = DerBuilder::new();
            builder.begin(DerType::Sequence);
            {
                builder.append_integer_from_u8(1);
                builder.append_octed_string_from_slice(&d);
            }
            builder.end();

            let pkcs8 = self.to_pkcs8(&builder.build(), false);
            let pkey = PKey::private_key_from_der(&pkcs8)?;

            Ok(EcdsaJwsSigner {
                algorithm: self.clone(),
                private_key: pkey,
                key_id: key_id.map(|val| val.to_string()),
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
            let pkcs8_ref = if self.detect_pkcs8(input.as_ref(), true)? {
                input.as_ref()
            } else {
                pkcs8 = self.to_pkcs8(input.as_ref(), true);
                &pkcs8
            };

            let pkey = PKey::public_key_from_der(pkcs8_ref)?;

            Ok(EcdsaJwsVerifier::new(self, pkey, None))
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
            let (alg, data) = parse_pem(input.as_ref())?;

            let pkcs8;
            let pkcs8_ref = match alg.as_str() {
                "PUBLIC KEY" => {
                    if !self.detect_pkcs8(&data, true)? {
                        bail!("PEM contents is expected PKCS#8 wrapped key.");
                    }
                    &data
                }
                "EC PUBLIC KEY" => {
                    pkcs8 = self.to_pkcs8(&data, true);
                    &pkcs8
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };

            let pkey = PKey::public_key_from_der(pkcs8_ref)?;

            Ok(EcdsaJwsVerifier::new(self, pkey, None))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a public key that is formatted by a JWK of EC type.
    ///
    /// # Arguments
    /// * `jwk` - A public key that is formatted by a JWK of EC type.
    pub fn verifier_from_jwk(&self, jwk: &Jwk) -> Result<EcdsaJwsVerifier, JoseError> {
        (|| -> anyhow::Result<EcdsaJwsVerifier> {
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
                _ => bail!("A parameter key_ops must contains vefify."),
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }

            match jwk.parameter("crv") {
                Some(Value::String(val)) if val == self.curve_name() => {}
                Some(Value::String(val)) => {
                    bail!("A parameter crv must be {} but {}", self.curve_name(), val)
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

            let pkcs8 = self.to_pkcs8(&vec, true);
            let pkey = PKey::public_key_from_der(&pkcs8)?;
            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(EcdsaJwsVerifier::new(self, pkey, key_id))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn curve_name(&self) -> &str {
        match self {
            Self::ES256 => "P-256",
            Self::ES384 => "P-384",
            Self::ES512 => "P-521",
            Self::ES256K => "secp256k1",
        }
    }

    fn curve_oid(&self) -> &ObjectIdentifier {
        match self {
            Self::ES256 => &*OID_PRIME256V1,
            Self::ES384 => &*OID_SECP384R1,
            Self::ES512 => &*OID_SECP521R1,
            Self::ES256K => &*OID_SECP256K1,
        }
    }

    fn curve_coordinate_size(&self) -> usize {
        match self {
            Self::ES256 => 32,
            Self::ES384 => 48,
            Self::ES512 => 66,
            Self::ES256K => 32,
        }
    }

    fn detect_pkcs8(&self, input: &[u8], is_public: bool) -> anyhow::Result<bool> {
        let mut reader = DerReader::from_reader(input);

        match reader.next() {
            Ok(Some(DerType::Sequence)) => {}
            _ => return Ok(false),
        }

        {
            if !is_public {
                // Version
                match reader.next() {
                    Ok(Some(DerType::Integer)) => match reader.to_u8() {
                        Ok(val) => {
                            if val != 0 {
                                return Ok(false);
                            }
                        }
                        _ => return Ok(false),
                    },
                    _ => return Ok(false),
                }
            }

            match reader.next() {
                Ok(Some(DerType::Sequence)) => {}
                _ => return Ok(false),
            }

            {
                match reader.next() {
                    Ok(Some(DerType::ObjectIdentifier)) => match reader.to_object_identifier() {
                        Ok(val) => {
                            if val != *OID_ID_EC_PUBLIC_KEY {
                                return Ok(false);
                            }
                        }
                        _ => return Ok(false),
                    },
                    _ => return Ok(false),
                }

                match reader.next() {
                    Ok(Some(DerType::ObjectIdentifier)) => match reader.to_object_identifier() {
                        Ok(val) => {
                            if &val != self.curve_oid() {
                                return Ok(false);
                            }
                        }
                        _ => return Ok(false),
                    },
                    _ => return Ok(false),
                }
            }
        }

        Ok(true)
    }

    fn to_pkcs8(&self, input: &[u8], is_public: bool) -> Vec<u8> {
        let mut builder = DerBuilder::new();
        builder.begin(DerType::Sequence);
        {
            if !is_public {
                builder.append_integer_from_u8(0);
            }

            builder.begin(DerType::Sequence);
            {
                builder.append_object_identifier(&OID_ID_EC_PUBLIC_KEY);
                builder.append_object_identifier(self.curve_oid());
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

impl JwsAlgorithm for EcdsaJwsAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
            Self::ES512 => "ES512",
            Self::ES256K => "ES256K",
        }
    }

    fn key_type(&self) -> &str {
        "EC"
    }
}

#[derive(Debug, Clone)]
pub struct EcdsaKeyPair {
    algorithm: EcdsaJwsAlgorithm,
    pkey: PKey<Private>,
}

impl EcdsaKeyPair {
    pub fn to_raw_private_key(&self) -> Vec<u8> {
        let ec_key = self.pkey.ec_key().unwrap();
        ec_key.private_key_to_der().unwrap()
    }

    pub fn to_traditional_pem_private_key(&self) -> Vec<u8> {
        let ec_key = self.pkey.ec_key().unwrap();
        ec_key.private_key_to_pem().unwrap()
    }

    fn to_jwk(&self, private: bool, public: bool) -> Jwk {
        let ec_key = self.pkey.ec_key().unwrap();

        let mut jwk = Jwk::new("EC");
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
        jwk.set_parameter(
            "crv",
            Some(Value::String({ self.algorithm.curve_name().to_string() })),
        )
        .unwrap();
        if private {
            let d = ec_key.private_key();
            let d = num_to_vec(&d, self.algorithm.curve_coordinate_size());
            let d = base64::encode_config(&d, base64::URL_SAFE_NO_PAD);

            jwk.set_parameter("d", Some(Value::String(d))).unwrap();
        }
        if public {
            let public_key = ec_key.public_key();
            let mut x = BigNum::new().unwrap();
            let mut y = BigNum::new().unwrap();
            let mut ctx = BigNumContext::new().unwrap();
            public_key
                .affine_coordinates_gfp(ec_key.group(), &mut x, &mut y, &mut ctx)
                .unwrap();

            let x = num_to_vec(&x, self.algorithm.curve_coordinate_size());
            let x = base64::encode_config(&x, base64::URL_SAFE_NO_PAD);

            let y = num_to_vec(&y, self.algorithm.curve_coordinate_size());
            let y = base64::encode_config(&y, base64::URL_SAFE_NO_PAD);

            jwk.set_parameter("x", Some(Value::String(x))).unwrap();
            jwk.set_parameter("y", Some(Value::String(y))).unwrap();
        }
        jwk
    }
}

impl KeyPair for EcdsaKeyPair {
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
pub struct EcdsaJwsSigner {
    algorithm: EcdsaJwsAlgorithm,
    private_key: PKey<Private>,
    key_id: Option<String>,
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

    fn set_key_id(&mut self, key_id: &str) {
        self.key_id = Some(key_id.to_string());
    }

    fn remove_key_id(&mut self) {
        self.key_id = None;
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let message_digest = match self.algorithm {
                EcdsaJwsAlgorithm::ES256 => MessageDigest::sha256(),
                EcdsaJwsAlgorithm::ES384 => MessageDigest::sha384(),
                EcdsaJwsAlgorithm::ES512 => MessageDigest::sha512(),
                EcdsaJwsAlgorithm::ES256K => MessageDigest::sha256(),
            };

            let mut signer = Signer::new(message_digest, &self.private_key)?;
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
}

#[derive(Debug, Clone)]
pub struct EcdsaJwsVerifier {
    algorithm: EcdsaJwsAlgorithm,
    public_key: PKey<Public>,
    key_id: Option<String>,
}

impl EcdsaJwsVerifier {
    fn new(
        algorithm: &EcdsaJwsAlgorithm,
        public_key: PKey<Public>,
        key_id: Option<String>,
    ) -> Self {
        Self {
            algorithm: algorithm.clone(),
            public_key,
            key_id,
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

    fn set_key_id(&mut self, key_id: &str) {
        self.key_id = Some(key_id.to_string());
    }

    fn remove_key_id(&mut self) {
        self.key_id = None;
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

            let message_digest = match self.algorithm {
                EcdsaJwsAlgorithm::ES256 => MessageDigest::sha256(),
                EcdsaJwsAlgorithm::ES384 => MessageDigest::sha384(),
                EcdsaJwsAlgorithm::ES512 => MessageDigest::sha512(),
                EcdsaJwsAlgorithm::ES256K => MessageDigest::sha256(),
            };

            let mut verifier = Verifier::new(message_digest, &self.public_key)?;
            verifier.update(message)?;
            verifier.verify(&der_signature)?;
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
                EcdsaJwsAlgorithm::ES256 => "pem/ECDSA_P-256_pkcs8_private.pem",
                EcdsaJwsAlgorithm::ES384 => "pem/ECDSA_P-384_pkcs8_private.pem",
                EcdsaJwsAlgorithm::ES512 => "pem/ECDSA_P-521_pkcs8_private.pem",
                EcdsaJwsAlgorithm::ES256K => "pem/ECDSA_secp256k1_pkcs8_private.pem",
            })?;
            let public_key = load_file(match alg {
                EcdsaJwsAlgorithm::ES256 => "pem/ECDSA_P-256_pkcs8_public.pem",
                EcdsaJwsAlgorithm::ES384 => "pem/ECDSA_P-384_pkcs8_public.pem",
                EcdsaJwsAlgorithm::ES512 => "pem/ECDSA_P-521_pkcs8_public.pem",
                EcdsaJwsAlgorithm::ES256K => "pem/ECDSA_secp256k1_pkcs8_public.pem",
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
                EcdsaJwsAlgorithm::ES256 => "der/ECDSA_P-256_pkcs8_private.der",
                EcdsaJwsAlgorithm::ES384 => "der/ECDSA_P-384_pkcs8_private.der",
                EcdsaJwsAlgorithm::ES512 => "der/ECDSA_P-521_pkcs8_private.der",
                EcdsaJwsAlgorithm::ES256K => "der/ECDSA_secp256k1_pkcs8_private.der",
            })?;
            let public_key = load_file(match alg {
                EcdsaJwsAlgorithm::ES256 => "der/ECDSA_P-256_pkcs8_public.der",
                EcdsaJwsAlgorithm::ES384 => "der/ECDSA_P-384_pkcs8_public.der",
                EcdsaJwsAlgorithm::ES512 => "der/ECDSA_P-521_pkcs8_public.der",
                EcdsaJwsAlgorithm::ES256K => "der/ECDSA_secp256k1_pkcs8_public.der",
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

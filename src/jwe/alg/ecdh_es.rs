use std::borrow::Cow;

use anyhow::bail;
use once_cell::sync::Lazy;
use openssl::pkey::{PKey, Private, Public};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::derive::Deriver;
use openssl::hash::MessageDigest;
use serde_json::{Map, Value};

use crate::der::oid::ObjectIdentifier;
use crate::der::{DerBuilder, DerType};
use crate::jose::{JoseHeader, JoseError};
use crate::jwe::{JweHeader, JweAlgorithm, JweDecrypter, JweEncrypter};
use crate::jwk::Jwk;
use crate::util;

static OID_PRIME256V1: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 3, 1, 7]));

static OID_SECP384R1: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 132, 0, 34]));

static OID_SECP521R1: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 132, 0, 35]));

static OID_SECP256K1: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 132, 0, 10]));

static OID_X25519: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 101, 110]));

static OID_X448: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 101, 111]));

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum EcdhEsCurve {
    P256,
    P384,
    P521,
    Secp256K1,
    X25519,
    X448,
}

impl EcdhEsCurve {
    pub fn name(&self) -> &str {
        match self {
            Self::P256 => "P-256",
            Self::P384 => "P-384",
            Self::P521 => "P-521",
            Self::Secp256K1 => "secp256k1",
            Self::X25519 => "X25519",
            Self::X448 => "X448",
        }
    }

    fn key_type(&self) -> &str {
        match self {
            Self::P256 => "EC",
            Self::P384 => "EC",
            Self::P521 => "EC",
            Self::Secp256K1 => "EC",
            Self::X25519 => "OKP",
            Self::X448 => "OKP",
        }
    }

    fn oid(&self) -> &ObjectIdentifier {
        match self {
            Self::P256 => &*OID_PRIME256V1,
            Self::P384 => &*OID_SECP384R1,
            Self::P521 => &*OID_SECP521R1,
            Self::Secp256K1 => &*OID_SECP256K1,
            Self::X25519 => &*OID_X25519,
            Self::X448 => &*OID_X448,
        }
    }
    
    fn nid(&self) -> Nid {
        match self {
            Self::P256 => Nid::X9_62_PRIME256V1,
            Self::P384 => Nid::SECP384R1,
            Self::P521 => Nid::SECP521R1,
            Self::Secp256K1 => Nid::SECP256K1,
            _ => unimplemented!(),
        }
    }

    fn coordinate_size(&self) -> usize {
        match self {
            Self::P256 | Self::Secp256K1 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
            Self::X25519 => 32,
            Self::X448 => 32,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum EcdhEsJweAlgorithm {
    /// Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF
    EcdhEs,
}

impl EcdhEsJweAlgorithm {
    pub fn encrypter_from_jwk(&self, jwk: &Jwk) -> Result<EcdhEsJweEncrypter, JoseError> {
        (|| -> anyhow::Result<EcdhEsJweEncrypter> {
            let key_type = match jwk.key_type() {
                val if val == "EC" || val == "OKP" => val,
                val => bail!("A parameter kty must be EC or OKP: {}", val),
            };
            match jwk.key_use() {
                Some(val) if val == "enc" => {}
                None => {}
                Some(val) => bail!("A parameter use must be enc: {}", val),
            }
            match jwk.key_operations() {
                Some(vals) => {
                    if !vals.iter().any(|e| e == "deriveKey")
                        || !vals.iter().any(|e| e == "deriveBits") {
                        bail!("A parameter key_ops must contains deriveKey and deriveBits.");
                    }
                },
                None => {},
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }
            let curve = match jwk.parameter("crv") {
                Some(Value::String(val)) => {
                    match key_type {
                        "EC" => match val.as_str() {
                            "P-256" => EcdhEsCurve::P256,
                            "P-384" => EcdhEsCurve::P384,
                            "P-521" => EcdhEsCurve::P521,
                            "secp256k1" => EcdhEsCurve::Secp256K1,
                            _ => bail!("EC key doesn't support the curve algorithm: {}", val),
                        },
                        "OKP" => match val.as_str() {
                            "X25519" => EcdhEsCurve::X25519,
                            "X448" => EcdhEsCurve::X448,
                            _ => bail!("OKP key doesn't support the curve algorithm: {}", val),
                        },
                        _ => bail!("A parameter crv is invalid: {}", val),
                    }
                }
                Some(_) => bail!("A parameter crv must be a string."),
                None => bail!("A parameter crv is required."),
            };
            let x = match jwk.parameter("x") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter x must be a string."),
                None => bail!("A parameter x is required."),
            };

            let public_key = match key_type {
                "EC" => {
                    let y = match jwk.parameter("y") {
                        Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                        Some(_) => bail!("A parameter y must be a string."),
                        None => bail!("A parameter y is required."),
                    };
        
                    let mut vec = Vec::with_capacity(1 + x.len() + y.len());
                    vec.push(0x04);
                    vec.extend_from_slice(&x);
                    vec.extend_from_slice(&y);
        
                    let pkcs8 = self.to_pkcs8(&vec, true, curve);
                    PKey::public_key_from_der(&pkcs8)?
                },
                "OKP" => {
                    let pkcs8 = self.to_pkcs8(&x, true, curve);
                    PKey::public_key_from_der(&pkcs8)?
                },
                _ => unreachable!(),
            };
            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(EcdhEsJweEncrypter {
                algorithm: self.clone(),
                curve,
                public_key,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn decrypter_from_jwk(&self, jwk: &Jwk) -> Result<EcdhEsJweDecrypter, JoseError> {
        (|| -> anyhow::Result<EcdhEsJweDecrypter> {
            let key_type = match jwk.key_type() {
                val if val == "EC" || val == "OKP" => val,
                val => bail!("A parameter kty must be EC or OKP: {}", val),
            };
            match jwk.key_use() {
                Some(val) if val == "enc" => {}
                None => {}
                Some(val) => bail!("A parameter use must be enc: {}", val),
            }
            match jwk.key_operations() {
                Some(vals) => {
                    if !vals.iter().any(|e| e == "deriveKey")
                        || !vals.iter().any(|e| e == "deriveBits") {
                        bail!("A parameter key_ops must contains deriveKey and deriveBits.");
                    }
                },
                None => {},
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }
            let curve = match jwk.parameter("crv") {
                Some(Value::String(val)) => {
                    match key_type {
                        "EC" => match val.as_str() {
                            "P-256" => EcdhEsCurve::P256,
                            "P-384" => EcdhEsCurve::P384,
                            "P-521" => EcdhEsCurve::P521,
                            "secp256k1" => EcdhEsCurve::Secp256K1,
                            _ => bail!("EC key doesn't support the curve algorithm: {}", val),
                        },
                        "OKP" => match val.as_str() {
                            "X25519" => EcdhEsCurve::X25519,
                            "X448" => EcdhEsCurve::X448,
                            _ => bail!("OKP key doesn't support the curve algorithm: {}", val),
                        },
                        _ => bail!("A parameter crv is invalid: {}", val),
                    }
                }
                Some(_) => bail!("A parameter crv must be a string."),
                None => bail!("A parameter crv is required."),
            };
            let d = match jwk.parameter("d") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter d must be a string."),
                None => bail!("A parameter d is required."),
            };

            let private_key = match key_type {
                "EC" => {
                    let mut builder = DerBuilder::new();
                    builder.begin(DerType::Sequence);
                    {
                        builder.append_integer_from_u8(1);
                        builder.append_octed_string_from_slice(&d);
                    }
                    builder.end();
        
                    let pkcs8 = self.to_pkcs8(&builder.build(), false, curve);
                    PKey::private_key_from_der(&pkcs8)?
                },
                "OKP" => {
                    let mut builder = DerBuilder::new();
                    builder.append_octed_string_from_slice(&d);

                    let pkcs8 = self.to_pkcs8(&builder.build(), false, curve);
                    PKey::private_key_from_der(&pkcs8)?
                },
                _ => unreachable!(),
            };
            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(EcdhEsJweDecrypter {
                algorithm: self.clone(),
                curve,
                private_key,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn to_pkcs8(&self, input: &[u8], is_public: bool, curve: EcdhEsCurve) -> Vec<u8> {
        let mut builder = DerBuilder::new();
        builder.begin(DerType::Sequence);
        {
            if !is_public {
                builder.append_integer_from_u8(0);
            }

            builder.begin(DerType::Sequence);
            {
                builder.append_object_identifier(curve.oid());
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

impl JweAlgorithm for EcdhEsJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::EcdhEs => "ECDH-ES",
        }
    }
        
    fn box_clone(&self) -> Box<dyn JweAlgorithm> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Clone)]
pub struct EcdhEsJweEncrypter {
    algorithm: EcdhEsJweAlgorithm,
    curve: EcdhEsCurve,
    public_key: PKey<Public>,
    key_id: Option<String>,
}

impl JweEncrypter for EcdhEsJweEncrypter {
    fn algorithm(&self) -> &dyn JweAlgorithm {
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

    fn encrypt(&self, header: &mut JweHeader, key_len: usize) -> Result<(Cow<[u8]>, Option<Vec<u8>>), JoseError> {
        (|| -> anyhow::Result<(Cow<[u8]>, Option<Vec<u8>>)> {
            header.set_algorithm(self.algorithm.name());

            let mut map = Map::new();
            map.insert("kty".to_string(), Value::String(self.curve.key_type().to_string()));
            map.insert("crv".to_string(), Value::String(self.curve.name().to_string()));

            let private_key = match self.curve.key_type() {
                "EC" => {
                    let ec_group = EcGroup::from_curve_name(self.curve.nid())?;
                    let ec_key = EcKey::generate(&ec_group)?;

                    let public_key = ec_key.public_key();
                    let mut x = BigNum::new()?;
                    let mut y = BigNum::new()?;
                    let mut ctx = BigNumContext::new()?;
                    public_key
                        .affine_coordinates_gfp(ec_key.group(), &mut x, &mut y, &mut ctx)?;

                    let x = util::num_to_vec(&x, self.curve.coordinate_size());
                    let x = base64::encode_config(&x, base64::URL_SAFE_NO_PAD);
                    map.insert("x".to_string(), Value::String(x));
            
                    let y = util::num_to_vec(&y, self.curve.coordinate_size());
                    let y = base64::encode_config(&y, base64::URL_SAFE_NO_PAD);
                    map.insert("y".to_string(), Value::String(y));

                    PKey::from_ec_key(ec_key)?
                }
                "OKP" => {
                    todo!("openssl-rust is not supported X25519 and X448");
                }
                _ => unreachable!(),
            };

            header.set_claim("epk", Some(Value::Object(map)))?;

            let mut deriver = Deriver::new(&private_key)?;
            deriver.set_peer(&self.public_key)?;
            let key = deriver.derive_to_vec()?;
            let key = util::contact_kdf(&key, key_len, MessageDigest::sha256());

            Ok((Cow::Owned(key), None))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }
    
    fn box_clone(&self) -> Box<dyn JweEncrypter> {
        Box::new(self.clone())
    }
}

#[derive(Debug, Clone)]
pub struct EcdhEsJweDecrypter {
    algorithm: EcdhEsJweAlgorithm,
    curve: EcdhEsCurve,
    private_key: PKey<Private>,
    key_id: Option<String>,
}

impl JweDecrypter for EcdhEsJweDecrypter {
    fn algorithm(&self) -> &dyn JweAlgorithm {
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

    fn decrypt(&self, header: &JweHeader, encrypted_key: &[u8], key_len: usize) -> Result<Cow<[u8]>, JoseError> {
        (|| -> anyhow::Result<Cow<[u8]>> {
            if encrypted_key.len() != 0 {
                bail!("The encrypted_key must be empty.");
            }

            let public_key = match header.claim("epk") {
                Some(Value::Object(map)) => {
                    match map.get("kty") {
                        Some(Value::String(val)) => {
                            if val != self.curve.key_type() {
                                bail!("The kty parameter in epk header claim is invalid: {}", val);
                            }
                        },
                        Some(_) => bail!("The kty parameter in epk header claim must be a string."),
                        None => bail!("The kty parameter in epk header claim is required."),
                    }

                    match map.get("crv") {
                        Some(Value::String(val)) => {
                            if val != self.curve.name() {
                                bail!("The crv parameter in epk header claim is invalid: {}", val);
                            }
                        },
                        Some(_) => bail!("The crv parameter in epk header claim must be a string."),
                        None => bail!("The crv parameter in epk header claim is required."),
                    }

                    match self.curve.key_type() {
                        "EC" => {
                            let x = match map.get("x") {
                                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                                Some(_) => bail!("The x parameter in epk header claim must be a string."),
                                None => bail!("The x parameter in epk header claim is required."),
                            };
                            let y = match map.get("y") {
                                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                                Some(_) => bail!("The x parameter in epk header claim must be a string."),
                                None => bail!("The x parameter in epk header claim is required."),
                            };

                            let mut vec = Vec::with_capacity(1 + x.len() + y.len());
                            vec.push(0x04);
                            vec.extend_from_slice(&x);
                            vec.extend_from_slice(&y);
                
                            let pkcs8 = self.algorithm.to_pkcs8(&vec, true, self.curve);
                            PKey::public_key_from_der(&pkcs8)?
                        },
                        "OKP" => {
                            let x = match map.get("x") {
                                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                                Some(_) => bail!("The x parameter in epk header claim must be a string."),
                                None => bail!("The x parameter in epk header claim is required."),
                            };

                            todo!("openssl-rust is not supported X25519 and X448");
                        },
                        _ => unreachable!(),
                    }
                },
                Some(_) => bail!("The epk header claim must be object."),
                None => bail!("This algorithm must have epk header claim."),
            };

            let mut deriver = Deriver::new(&self.private_key)?;
            deriver.set_peer(&public_key)?;
            let key = deriver.derive_to_vec()?;
            let key = util::contact_kdf(&key, key_len, MessageDigest::sha256());

            Ok(Cow::Owned(key))
        })()
        .map_err(|err| JoseError::InvalidJweFormat(err))
    }
        
    fn box_clone(&self) -> Box<dyn JweDecrypter> {
        Box::new(self.clone())
    }
}
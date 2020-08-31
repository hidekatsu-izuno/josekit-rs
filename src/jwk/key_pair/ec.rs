use std::fmt::Display;
use std::ops::Deref;

use once_cell::sync::Lazy;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use serde_json::Value;

use crate::der::{oid::ObjectIdentifier, DerBuilder, DerReader, DerType};
use crate::jose::JoseError;
use crate::jwk::{Jwk, KeyPair};
use crate::util::num_to_vec;

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
pub enum EcCurve {
    P256,
    P384,
    P521,
    Secp256K1,
}

impl EcCurve {
    pub fn name(&self) -> &str {
        match self {
            Self::P256 => "P-256",
            Self::P384 => "P-384",
            Self::P521 => "P-521",
            Self::Secp256K1 => "secp256k1",
        }
    }

    pub fn oid(&self) -> &ObjectIdentifier {
        match self {
            Self::P256 => &OID_PRIME256V1,
            Self::P384 => &OID_SECP384R1,
            Self::P521 => &OID_SECP521R1,
            Self::Secp256K1 => &OID_SECP256K1,
        }
    }

    fn nid(&self) -> Nid {
        match self {
            Self::P256 => Nid::X9_62_PRIME256V1,
            Self::P384 => Nid::SECP384R1,
            Self::P521 => Nid::SECP521R1,
            Self::Secp256K1 => Nid::SECP256K1,
        }
    }

    fn coordinate_size(&self) -> usize {
        match self {
            Self::P256 | Self::Secp256K1 => 32,
            Self::P384 => 48,
            Self::P521 => 66,
        }
    }
}

impl Display for EcCurve {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

#[derive(Debug, Clone)]
pub struct EcKeyPair {
    private_key: PKey<Private>,
    curve: EcCurve,
    alg: Option<String>,
}

impl EcKeyPair {
    pub(crate) fn from_private_key(private_key: PKey<Private>, curve: EcCurve) -> EcKeyPair {
        EcKeyPair {
            private_key,
            curve,
            alg: None,
        }
    }

    pub(crate) fn into_private_key(self) -> PKey<Private> {
        self.private_key
    }

    /// Generate EC key pair.
    pub fn generate(curve: EcCurve) -> Result<EcKeyPair, JoseError> {
        (|| -> anyhow::Result<EcKeyPair> {
            let ec_group = EcGroup::from_curve_name(curve.nid())?;
            let ec_key = EcKey::generate(&ec_group)?;
            let private_key = PKey::from_ec_key(ec_key)?;

            Ok(EcKeyPair {
                curve,
                private_key,
                alg: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn to_raw_private_key(&self) -> Vec<u8> {
        let ec_key = self.private_key.ec_key().unwrap();
        ec_key.private_key_to_der().unwrap()
    }

    pub fn to_traditional_pem_private_key(&self) -> Vec<u8> {
        let ec_key = self.private_key.ec_key().unwrap();
        ec_key.private_key_to_pem().unwrap()
    }

    fn to_jwk(&self, private: bool, public: bool) -> Jwk {
        let ec_key = self.private_key.ec_key().unwrap();

        let mut jwk = Jwk::new("EC");
        if let Some(val) = &self.alg {
            jwk.set_algorithm(val);
        }
        jwk.set_parameter("crv", Some(Value::String(self.curve.to_string())))
            .unwrap();
        if private {
            let d = ec_key.private_key();
            let d = num_to_vec(&d, self.curve.coordinate_size());
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

            let x = num_to_vec(&x, self.curve.coordinate_size());
            let x = base64::encode_config(&x, base64::URL_SAFE_NO_PAD);

            let y = num_to_vec(&y, self.curve.coordinate_size());
            let y = base64::encode_config(&y, base64::URL_SAFE_NO_PAD);

            jwk.set_parameter("x", Some(Value::String(x))).unwrap();
            jwk.set_parameter("y", Some(Value::String(y))).unwrap();
        }
        jwk
    }

    pub(crate) fn detect_pkcs8(input: &[u8], is_public: bool) -> Option<EcCurve> {
        let curve;
        let mut reader = DerReader::from_reader(input);

        match reader.next() {
            Ok(Some(DerType::Sequence)) => {}
            _ => return None,
        }

        {
            if !is_public {
                // Version
                match reader.next() {
                    Ok(Some(DerType::Integer)) => match reader.to_u8() {
                        Ok(val) => {
                            if val != 0 {
                                return None;
                            }
                        }
                        _ => return None,
                    },
                    _ => return None,
                }
            }

            match reader.next() {
                Ok(Some(DerType::Sequence)) => {}
                _ => return None,
            }

            {
                match reader.next() {
                    Ok(Some(DerType::ObjectIdentifier)) => match reader.to_object_identifier() {
                        Ok(val) => {
                            if val != *OID_ID_EC_PUBLIC_KEY {
                                return None;
                            }
                        }
                        _ => return None,
                    },
                    _ => return None,
                }

                curve = match reader.next() {
                    Ok(Some(DerType::ObjectIdentifier)) => match reader.to_object_identifier() {
                        Ok(val) if val == *OID_PRIME256V1 => EcCurve::P256,
                        Ok(val) if val == *OID_SECP384R1 => EcCurve::P384,
                        Ok(val) if val == *OID_SECP521R1 => EcCurve::P521,
                        Ok(val) if val == *OID_SECP256K1 => EcCurve::Secp256K1,
                        _ => return None,
                    },
                    _ => return None,
                }
            }
        }

        Some(curve)
    }

    pub(crate) fn to_pkcs8(input: &[u8], is_public: bool, curve: EcCurve) -> Vec<u8> {
        let mut builder = DerBuilder::new();
        builder.begin(DerType::Sequence);
        {
            if !is_public {
                builder.append_integer_from_u8(0);
            }

            builder.begin(DerType::Sequence);
            {
                builder.append_object_identifier(&OID_ID_EC_PUBLIC_KEY);
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

impl KeyPair for EcKeyPair {
    fn set_algorithm(&mut self, value: Option<&str>) {
        self.alg = value.map(|val| val.to_string());
    }

    fn algorithm(&self) -> Option<&str> {
        match &self.alg {
            Some(val) => Some(val.as_str()),
            None => None,
        }
    }

    fn to_der_private_key(&self) -> Vec<u8> {
        self.private_key.private_key_to_der().unwrap()
    }

    fn to_der_public_key(&self) -> Vec<u8> {
        self.private_key.public_key_to_der().unwrap()
    }

    fn to_pem_private_key(&self) -> Vec<u8> {
        self.private_key.private_key_to_pem_pkcs8().unwrap()
    }

    fn to_pem_public_key(&self) -> Vec<u8> {
        self.private_key.public_key_to_pem().unwrap()
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

    fn box_clone(&self) -> Box<dyn KeyPair> {
        Box::new(self.clone())
    }
}

impl Deref for EcKeyPair {
    type Target = dyn KeyPair;

    fn deref(&self) -> &Self::Target {
        self
    }
}

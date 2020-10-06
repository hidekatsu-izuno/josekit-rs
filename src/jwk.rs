//! JSON Web Key (JWK) support.

pub mod alg;

mod jwk;
mod jwk_set;
mod key_pair;

use anyhow::bail;

use crate::der::{DerReader, DerType};
use crate::JoseError;
use crate::jwk::alg::rsa::RsaKeyPair;
use crate::jwk::alg::rsapss::RsaPssKeyPair;
use crate::jwk::alg::ec::EcKeyPair;
use crate::jwk::alg::ed::EdKeyPair;
use crate::jwk::alg::ecx::EcxKeyPair;
use crate::util;
use crate::util::oid::{OID_RSA_ENCRYPTION, OID_RSASSA_PSS, OID_ID_EC_PUBLIC_KEY, OID_ED25519, OID_ED448, OID_X25519, OID_X448};

pub use crate::jwk::jwk::Jwk;
pub use crate::jwk::jwk_set::JwkSet;
pub use crate::jwk::key_pair::KeyPair;

pub use crate::jwk::alg::ec::EcCurve::Secp256k1;
pub use crate::jwk::alg::ec::EcCurve::P256 as P_256;
pub use crate::jwk::alg::ec::EcCurve::P384 as P_384;
pub use crate::jwk::alg::ec::EcCurve::P521 as P_521;

pub use crate::jwk::alg::ed::EdCurve::Ed25519;
pub use crate::jwk::alg::ed::EdCurve::Ed448;

pub use crate::jwk::alg::ecx::EcxCurve::X25519;
pub use crate::jwk::alg::ecx::EcxCurve::X448;

pub fn key_pair_from_bytes(input: &impl AsRef<[u8]>) -> Result<Box<dyn KeyPair>, JoseError> {
    (|| -> anyhow::Result<Box<dyn KeyPair>> {
        let input = input.as_ref();
        if input.len() == 0 {
            bail!("A input must not be empty.");
        }

        let key_pair: Box<dyn KeyPair> = match input[0] {
            // DER or Raw
            b'\x10' => key_pair_from_der(input)?,
            // PEM
            b'=' => {
                let (alg, data) = util::parse_pem(input.as_ref())?;
                match alg.as_str() {
                    "PRIVATE KEY" => key_pair_from_der(&data)?,
                    "RSA PRIVATE KEY" => {
                        let key_pair = RsaKeyPair::from_der(&data)?;
                        Box::new(key_pair)
                    },
                    "RSA-PSS PRIVATE KEY" => {
                        let key_pair = RsaPssKeyPair::from_der(&data, None, None, None)?;
                        Box::new(key_pair)
                    },
                    "EC PRIVATE KEY" => {
                        let key_pair = EcKeyPair::from_der(&data, None)?;
                        Box::new(key_pair)
                    },
                    "ED25519 PRIVATE KEY" | "ED448 PRIVATE KEY" => {
                        let key_pair = EdKeyPair::from_der(&data)?;
                        Box::new(key_pair)
                    }
                    "X25519 PRIVATE KEY" | "X448 PRIVATE KEY" => {
                        let key_pair = EcxKeyPair::from_der(&data)?;
                        Box::new(key_pair)
                    },
                    val => if val.contains("PUBLIC KEY") {
                        bail!("A input may be a public key, not private.");
                    } else {
                        bail!("Unknown key type: {}", val);
                    }, 
                }
            },
            // JWK
            _ => {
                let jwk = Jwk::from_bytes(input)?;
                match jwk.key_type() {
                    "oct" => bail!("The key type 'oct' doesn't have a public key."),
                    "RSA" => {
                        let key_pair = RsaKeyPair::from_jwk(&jwk)?;
                        Box::new(key_pair)
                    },
                    "EC" => match jwk.curve() {
                        Some("P-256") | Some("P-384") | Some("P-521") | Some("secp256k1") => {
                            let key_pair = EcKeyPair::from_jwk(&jwk)?;
                            Box::new(key_pair)
                        },
                        Some(val) => bail!("Unknown curve: {}", val),
                        None => bail!("A Curve name is missing."),
                    },
                    "OKP" => match jwk.curve() {
                        Some("Ed25519") | Some("Ed448") => {
                            let key_pair = EdKeyPair::from_jwk(&jwk)?;
                            Box::new(key_pair)
                        },
                        Some("X25519") | Some("X448") => {
                            let key_pair = EcxKeyPair::from_jwk(&jwk)?;
                            Box::new(key_pair)
                        },
                        Some(val) => bail!("Unknown curve: {}", val),
                        None => bail!("A Curve name is missing."),
                    },
                    val => bail!("Unknown key type: {}", val),
                }
            }
        };

        Ok(key_pair)
    })()
    .map_err(|err| JoseError::InvalidKeyFormat(err))
}

fn key_pair_from_der(input: &[u8]) -> anyhow::Result<Box<dyn KeyPair>> {
    let mut reader = DerReader::from_reader(input.as_ref());

    match reader.next()? {
        Some(DerType::Sequence) => {},
        Some(val) => bail!("The next token was expected to be a sequence, but it was other type: {}", val),
        None => bail!("The next token was expected to be a sequence, but it was missing."),
    }

    let is_private = match reader.next()? {
        Some(DerType::Sequence) => true,
        Some(DerType::Integer) => false,
        Some(val) => bail!("The next token was expected to be a sequence or a integer, but it was other type: {}", val),
        None => bail!("The next token was expected to be a sequence or a integer, but it was missing."),
    };

    let key_pair: Box<dyn KeyPair> = if is_private {
        match reader.next()? {
            Some(DerType::ObjectIdentifier) => match reader.to_object_identifier()? {
                val if val == *OID_RSA_ENCRYPTION => {
                    let key_pair = RsaKeyPair::from_der(input)?;
                    Box::new(key_pair)
                },
                val if val == *OID_RSASSA_PSS => {
                    let key_pair = RsaPssKeyPair::from_der(input, None, None, None)?;
                    Box::new(key_pair)
                },
                val if val == *OID_ID_EC_PUBLIC_KEY => {
                    let key_pair = EcKeyPair::from_der(input, None)?;
                    Box::new(key_pair)
                },
                val if val == *OID_ED25519 || val == *OID_ED448 => {
                    let key_pair = EdKeyPair::from_der(input)?;
                    Box::new(key_pair)
                },
                val if val == *OID_X25519 || val == *OID_X448 => {
                    let key_pair = EcxKeyPair::from_der(input)?;
                    Box::new(key_pair)
                },
                val => bail!("Unexpected oid: {}", val),
            },
            Some(val) => bail!("The next token was expected to be a oid, but it was other type: {}", val),
            None => bail!("The next token was expected to be a oid, but it was missing."),
        }
    } else {
        let mut n_count = 0;
        let mut last_type = None;
        loop {
            match reader.next()? {
                Some(DerType::Integer) => {
                    n_count += 1;
                },
                val => {
                    last_type = val;
                    break;
                }
            }
        }

        match (n_count, last_type) {
            // RSAPrivateKey
            (9, Some(DerType::Sequence)) | (9, Some(DerType::EndOfContents)) => {
                let key_pair = RsaKeyPair::from_der(input)?;
                Box::new(key_pair)
            },
            // ECPrivateKey
            (1, Some(DerType::OctetString)) => {   
                let key_pair = EcKeyPair::from_der(input, None)?;
                Box::new(key_pair)
            },
            // SubjectPublicKeyInfo
            (1, Some(DerType::Sequence)) => {
                bail!("A input is maybe a public key, not private.");
            },
            // RSAPublicKey
            (2, Some(DerType::EndOfContents)) => {
                bail!("A input is maybe a public key, not private.");
            },
            (_, Some(val)) => bail!("Unexpected token: {}", val),
            (_, None) => bail!("Unexpected token: {}", DerType::Integer),
        }
    };

    Ok(key_pair)
}
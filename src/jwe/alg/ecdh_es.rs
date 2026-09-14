use std::borrow::Cow;
#[cfg(feature = "rustcrypto")]
use std::fmt::Debug;
use std::fmt::Display;
use std::ops::Deref;

use anyhow::bail;

#[cfg(feature = "openssl")]
use openssl::{
    aes::{self, AesKey},
    derive::Deriver,
    hash::{Hasher, MessageDigest},
    pkey::{PKey, Private, Public},
};
#[cfg(feature = "rustcrypto")]
use rsa::pkcs8::{
    der::{
        asn1::{BitStringRef, OctetStringRef},
        Decode,
    },
    PrivateKeyInfoRef, SubjectPublicKeyInfoRef,
};

#[cfg(feature = "rustcrypto")]
use crate::{
    jwe::alg::aeskw::{aes, AesKey},
    jwk::alg::ed::EdCurve,
};

use crate::jwe::{JweAlgorithm, JweContentEncryption, JweDecrypter, JweEncrypter, JweHeader};
use crate::jwk::alg::{
    ec::{EcCurve, EcKeyPair},
    ecx::{EcxCurve, EcxKeyPair},
};
use crate::jwk::Jwk;
#[cfg(feature = "rustcrypto")]
use crate::jwk::PublicKey as PublicKeyTrait;
use crate::util;
use crate::util::der::{DerReader, DerType};

use crate::util::oid::{
    OID_ID_EC_PUBLIC_KEY, OID_PRIME256V1, OID_SECP256K1, OID_SECP384R1, OID_SECP521R1, OID_X25519,
    OID_X448,
};
use crate::{JoseError, JoseHeader, Map, Value};

#[cfg(feature = "rustcrypto")]
#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum PublicKey {
    P256(p256::PublicKey),
    P384(p384::PublicKey),
    P521(p521::PublicKey),
    K256(k256::PublicKey),
    X25519(x25519_dalek::PublicKey),
    X448(cx448::x448::PublicKey),
    Ed25519(ed25519_dalek::VerifyingKey),
    Ed448(cx448::VerifyingKey),
}
#[cfg(feature = "rustcrypto")]
impl PublicKey {
    pub fn ec_key_x(&self) -> Vec<u8> {
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        match self {
            PublicKey::P256(public_key) => public_key.to_encoded_point(false).x().unwrap().to_vec(),
            PublicKey::P384(public_key) => public_key.to_encoded_point(false).x().unwrap().to_vec(),
            PublicKey::P521(public_key) => public_key.to_encoded_point(false).x().unwrap().to_vec(),
            PublicKey::K256(public_key) => public_key.to_encoded_point(false).x().unwrap().to_vec(),
            PublicKey::X25519(public_key) => public_key.to_bytes().to_vec(),
            PublicKey::X448(public_key) => public_key.as_bytes().to_vec(),
            PublicKey::Ed25519(verifying_key) => verifying_key.as_bytes().to_vec(),
            PublicKey::Ed448(verifying_key) => verifying_key.as_bytes().to_vec(),
        }
    }
    pub fn ec_key_y(&self) -> Vec<u8> {
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        match self {
            PublicKey::P256(public_key) => public_key.to_encoded_point(false).y().unwrap().to_vec(),
            PublicKey::P384(public_key) => public_key.to_encoded_point(false).y().unwrap().to_vec(),
            PublicKey::P521(public_key) => public_key.to_encoded_point(false).y().unwrap().to_vec(),
            PublicKey::K256(public_key) => public_key.to_encoded_point(false).y().unwrap().to_vec(),
            PublicKey::X25519(_) => unimplemented!("x25519 only uses single coordinate"),
            PublicKey::X448(_) => unimplemented!("X448 only uses single coordinate"),
            PublicKey::Ed25519(_verifying_key) => {
                unimplemented!("ed25519 only uses single coordinate")
            }
            PublicKey::Ed448(_verifying_key) => unimplemented!("ed448 only uses single coordinate"),
        }
    }
    pub fn ec_key_der(&self) -> Result<Vec<u8>, anyhow::Error> {
        match self {
            PublicKey::P256(key) => {
                use p256::pkcs8::EncodePublicKey;
                Ok(key.to_public_key_der().unwrap().to_vec())
            }
            PublicKey::P384(key) => {
                use p384::pkcs8::EncodePublicKey;
                Ok(key.to_public_key_der().unwrap().to_vec())
            }
            PublicKey::P521(key) => {
                use p521::pkcs8::EncodePublicKey;
                Ok(key.to_public_key_der().unwrap().to_vec())
            }
            PublicKey::K256(key) => {
                use k256::pkcs8::EncodePublicKey;
                Ok(key.to_public_key_der().unwrap().to_vec())
            }
            PublicKey::X25519(key) => Ok(ed25519_public_to_ec_der(key.as_bytes(), true)),
            PublicKey::X448(key) => Ok(ed448_public_to_ec_der(key.as_bytes(), true)),
            PublicKey::Ed25519(key) => Ok(ed25519_public_to_ec_der(key.as_bytes(), false)),
            PublicKey::Ed448(key) => Ok(ed448_public_to_ec_der(key.as_bytes(), false)),
        }
    }
    pub fn ec_key_pem(&self) -> Result<String, anyhow::Error> {
        match self {
            PublicKey::P256(key) => {
                use p256::pkcs8::EncodePublicKey;
                use rsa::pkcs8::LineEnding;
                Ok(key.to_public_key_pem(LineEnding::CRLF).unwrap())
            }
            PublicKey::P384(key) => {
                use p384::pkcs8::EncodePublicKey;
                use rsa::pkcs8::LineEnding;
                Ok(key.to_public_key_pem(LineEnding::CRLF).unwrap())
            }
            PublicKey::P521(key) => {
                use p521::pkcs8::EncodePublicKey;
                use rsa::pkcs8::LineEnding;
                Ok(key.to_public_key_pem(LineEnding::CRLF).unwrap())
            }
            PublicKey::K256(key) => {
                use k256::pkcs8::EncodePublicKey;
                use rsa::pkcs8::LineEnding;
                Ok(key.to_public_key_pem(LineEnding::CRLF).unwrap())
            }
            PublicKey::X25519(key) => {
                use rsa::pkcs1::pem::PemLabel;

                let bytes = ed25519_public_to_ec_der(key.as_bytes(), true);
                let p = pem::Pem::new(SubjectPublicKeyInfoRef::PEM_LABEL, bytes);
                Ok(pem::encode(&p))
            }
            PublicKey::X448(key) => {
                use rsa::pkcs1::pem::PemLabel;
                let bytes = ed448_public_to_ec_der(key.as_bytes(), true);
                let p = pem::Pem::new(SubjectPublicKeyInfoRef::PEM_LABEL, bytes);
                Ok(pem::encode(&p))
            }
            PublicKey::Ed25519(key) => {
                // Ok(ed25519_public_to_ec_der(key.as_bytes(), false))
                use rsa::pkcs1::pem::PemLabel;
                let bytes = ed25519_public_to_ec_der(key.as_bytes(), false);
                let p = pem::Pem::new(SubjectPublicKeyInfoRef::PEM_LABEL, bytes);
                Ok(pem::encode(&p))
            }
            PublicKey::Ed448(key) => {
                use rsa::pkcs1::pem::PemLabel;
                let bytes = ed448_public_to_ec_der(key.as_bytes(), false);
                let p = pem::Pem::new(SubjectPublicKeyInfoRef::PEM_LABEL, bytes);
                Ok(pem::encode(&p))
            }
        }
    }
    pub fn ec_key_jwk(&self) -> Result<String, anyhow::Error> {
        Ok(PublicKeyTrait::to_jwk(self).to_string())
    }
    pub fn from_pkcs8_der_with_ed_curve(
        curve: EdCurve,
        spki: &[u8],
    ) -> Result<Self, anyhow::Error> {
        Ok(match curve {
            EdCurve::Ed25519 => PublicKey::Ed25519(ed25519_dalek::VerifyingKey::from_bytes(
                &ed25519_public_from_der_spki(&spki)?,
            )?),
            EdCurve::Ed448 => PublicKey::Ed448(cx448::VerifyingKey::from_bytes(
                &ed448_verifying_from_der_spki(spki)?,
            )?),
        })
    }
    pub fn from_pkcs8_der_with_ec_curve(
        curve: EcCurve,
        spki: &[u8],
    ) -> Result<Self, anyhow::Error> {
        use anyhow::Context;
        Ok(match curve {
            EcCurve::P256 => {
                use p256::pkcs8::DecodePublicKey;
                PublicKey::P256(
                    p256::PublicKey::from_public_key_der(&spki).context("p256 parsing failed")?,
                )
            }
            EcCurve::P384 => {
                use p384::pkcs8::DecodePublicKey;
                PublicKey::P384(
                    p384::PublicKey::from_public_key_der(&spki).context("p384 parsing failed")?,
                )
            }
            EcCurve::P521 => {
                use p521::pkcs8::DecodePublicKey;
                PublicKey::P521(
                    p521::PublicKey::from_public_key_der(&spki).context("p521 parsing failed")?,
                )
            }
            EcCurve::Secp256k1 => {
                use k256::pkcs8::DecodePublicKey;
                PublicKey::K256(
                    k256::PublicKey::from_public_key_der(&spki).context("k256 parsing failed")?,
                )
            }
        })
    }
    fn from_pkcs8_der(key_type: EcdhEsKeyType, spki: &[u8]) -> Result<Self, anyhow::Error> {
        use anyhow::Context;
        Ok(match key_type {
            EcdhEsKeyType::Ec(ec_curve) => match ec_curve {
                EcCurve::P256 => {
                    use p256::pkcs8::DecodePublicKey;
                    PublicKey::P256(
                        p256::PublicKey::from_public_key_der(&spki)
                            .context("p256 parsing failed")?,
                    )
                }
                EcCurve::P384 => {
                    use p384::pkcs8::DecodePublicKey;
                    PublicKey::P384(
                        p384::PublicKey::from_public_key_der(&spki)
                            .context("p384 parsing failed")?,
                    )
                }
                EcCurve::P521 => {
                    use p521::pkcs8::DecodePublicKey;
                    PublicKey::P521(
                        p521::PublicKey::from_public_key_der(&spki)
                            .context("p521 parsing failed")?,
                    )
                }
                EcCurve::Secp256k1 => {
                    use k256::pkcs8::DecodePublicKey;
                    PublicKey::K256(
                        k256::PublicKey::from_public_key_der(&spki)
                            .context("k256 parsing failed")?,
                    )
                }
            },
            EcdhEsKeyType::Ecx(ecx_curve) => match ecx_curve {
                EcxCurve::X25519 => PublicKey::X25519(x25519_dalek::PublicKey::from(
                    ed25519_public_from_der_spki(&spki)?,
                )),
                EcxCurve::X448 => PublicKey::X448(
                    cx448::x448::PublicKey::from_bytes(&ed448_public_from_der_spki(spki)?)
                        .context("x448 parsing failed")?,
                ),
            },
        })
    }
    pub fn verify_signature(&self, msg: &[u8], signature: &[u8]) -> Result<(), anyhow::Error> {
        match self {
            PublicKey::P256(public_key) => {
                use p256::ecdsa::signature::Verifier;
                let signature = p256::ecdsa::Signature::from_der(signature)?;
                let verifying_key: p256::ecdsa::VerifyingKey = public_key.into();
                verifying_key.verify(msg, &signature)?;
                Ok(())
            }
            PublicKey::P384(public_key) => {
                use p384::ecdsa::signature::Verifier;
                let signature = p384::ecdsa::Signature::from_der(signature)?;
                let verifying_key: p384::ecdsa::VerifyingKey = public_key.into();
                verifying_key.verify(msg, &signature)?;
                Ok(())
            }
            PublicKey::P521(public_key) => {
                use p521::ecdsa::signature::Verifier;
                let signature = p521::ecdsa::Signature::from_der(signature)?;
                let verifying_key: p521::ecdsa::VerifyingKey =
                    p521::ecdsa::VerifyingKey::from_affine(public_key.as_affine().to_owned())?;
                verifying_key.verify(msg, &signature)?;
                Ok(())
            }
            PublicKey::K256(public_key) => {
                use crate::jwe::alg::pbes2_hmac_aeskw::MessageDigest;
                let signature = k256::ecdsa::Signature::from_der(signature)?;
                let md = MessageDigest::sha256();
                let hash = md.hash(&msg);
                //TODO: find out why the default hash does not work with sha256
                k256::ecdsa::hazmat::verify_prehashed(
                    &public_key.to_projective(),
                    k256::FieldBytes::from_slice(&hash),
                    &signature,
                )?;
                Ok(())
            }
            PublicKey::X25519(_) => unimplemented!("x25519 is a DH protocol"),
            PublicKey::X448(_) => unimplemented!("x25519 is a DH protocol"),
            PublicKey::Ed25519(verifying_key) => {
                use ed25519_dalek::Verifier;
                let signature = ed25519_dalek::Signature::from_slice(signature)?;
                verifying_key.verify(msg, &signature)?;
                Ok(())
            }
            PublicKey::Ed448(verifying_key) => {
                use cx448::crypto_signature::Verifier;
                let signature = cx448::Signature::try_from(signature)?;
                println!("after signature parsing");
                verifying_key.verify(msg, &signature)?;
                Ok(())
            }
        }
    }
    pub fn verify_signature_prehashed(
        &self,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), anyhow::Error> {
        match self {
            PublicKey::Ed25519(verifying_key) => {
                use ed25519_dalek::{Digest, DigestVerifier};
                let signature = ed25519_dalek::Signature::from_slice(signature)?;
                verifying_key.verify_digest(
                    |d: &mut ed25519_dalek::Sha512| {
                        d.update(ed25519_dalek::Sha512::digest(message));
                        Ok(())
                    },
                    &signature,
                )?;
                Ok(())
            }
            PublicKey::Ed448(_verifying_key) => {
                // use cx448::crypto_signature::DigestVerifier as Ed448DigestVerifier;
                // use cx448::sha3::Digest;

                // let signature = cx448::Signature::try_from(signature)?;
                println!("after signature parsing");
                // Ed448DigestVerifier::verify_digest(
                //     verifying_key,
                //     |d: &mut cx448::sha3::Sha3_512| {
                //         cx448::sha3::Digest::update(d, cx448::sha3::Sha3_512::digest(message));
                //     },
                //     &signature,
                // )?;
                // Ok(())
                unimplemented!("Trait issues")
            }
            _ => self.verify_signature(message, signature),
        }
    }
}

#[cfg(feature = "rustcrypto")]
impl PublicKeyTrait for PublicKey {
    fn to_der_public_key(&self) -> Vec<u8> {
        self.ec_key_der().unwrap()
    }

    fn to_pem_public_key(&self) -> Vec<u8> {
        self.ec_key_pem().unwrap().into_bytes()
    }

    fn to_jwk_public_key(&self) -> Jwk {
        let (key_type, curve) = match self {
            PublicKey::P256(_) => ("EC", "P-256"),
            PublicKey::P384(_) => ("EC", "P-384"),
            PublicKey::P521(_) => ("EC", "P-521"),
            PublicKey::K256(_) => ("EC", "secp256k1"),
            PublicKey::X25519(_) => ("OKP", "X25519"),
            PublicKey::X448(_) => ("OKP", "X448"),
            PublicKey::Ed25519(_) => ("OKP", "Ed25519"),
            PublicKey::Ed448(_) => ("OKP", "Ed448"),
        };

        let mut jwk = Jwk::new(key_type);
        jwk.set_parameter("crv", Some(Value::String(curve.to_owned())))
            .unwrap();
        jwk.set_parameter(
            "x",
            Some(Value::String(util::encode_base64_urlsafe_nopad(
                self.ec_key_x(),
            ))),
        )
        .unwrap();

        if matches!(
            self,
            PublicKey::P256(_) | PublicKey::P384(_) | PublicKey::P521(_) | PublicKey::K256(_)
        ) {
            jwk.set_parameter(
                "y",
                Some(Value::String(util::encode_base64_urlsafe_nopad(
                    self.ec_key_y(),
                ))),
            )
            .unwrap();
        }
        if matches!(self, PublicKey::Ed25519(_) | PublicKey::Ed448(_)) {
            jwk.set_key_use("sig");
        } else if matches!(self, PublicKey::X25519(_) | PublicKey::X448(_)) {
            jwk.set_key_use("enc");
        }
        jwk
    }
}
#[cfg(feature = "rustcrypto")]
#[derive(Clone)]
pub enum PrivateKey {
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    P521(p521::SecretKey),
    K256(k256::SecretKey),
    X25519(x25519_dalek::StaticSecret),
    X448(cx448::x448::Secret),
    Ed25519(ed25519_dalek::SigningKey),
    Ed448(cx448::SigningKey),
}
#[cfg(feature = "rustcrypto")]
impl Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrivateKey::P256(_) => write!(f, "P256"),
            PrivateKey::P384(_) => write!(f, "P384"),
            PrivateKey::P521(_) => write!(f, "P521"),
            PrivateKey::K256(_) => write!(f, "K256"),
            PrivateKey::X25519(_) => write!(f, "X25519"),
            PrivateKey::X448(_) => write!(f, "X448"),
            PrivateKey::Ed25519(_) => write!(f, "Ed25519"),
            PrivateKey::Ed448(_) => write!(f, "Ed448"),
        }
    }
}
#[cfg(feature = "rustcrypto")]
pub fn ed25519_public_from_der_spki(key_bytes: &[u8]) -> Result<[u8; 32], anyhow::Error> {
    let spki = SubjectPublicKeyInfoRef::from_der(&key_bytes)?;
    if spki.subject_public_key.raw_bytes().len() != 32 {
        return Err(anyhow::anyhow!("Invalid Ed25519 public key"));
    }
    let mut x_bytes = [0; 32];
    x_bytes.copy_from_slice(&spki.subject_public_key.raw_bytes()[..]);
    Ok(x_bytes)
}
#[cfg(feature = "rustcrypto")]
pub fn ed448_public_from_der_spki(key_bytes: &[u8]) -> Result<[u8; 56], anyhow::Error> {
    let spki = SubjectPublicKeyInfoRef::from_der(&key_bytes)?;
    if spki.subject_public_key.raw_bytes().len() != 56
        && spki.subject_public_key.raw_bytes().len() != 57
    {
        return Err(anyhow::anyhow!("=> Invalid Ed448 public key"));
    }
    println!("{}", spki.subject_public_key.raw_bytes().len());
    let mut x_bytes = [0; 56];
    x_bytes.copy_from_slice(&spki.subject_public_key.raw_bytes()[..56]);
    Ok(x_bytes)
}
#[cfg(feature = "rustcrypto")]
pub fn ed448_verifying_from_der_spki(key_bytes: &[u8]) -> Result<[u8; 57], anyhow::Error> {
    let spki = SubjectPublicKeyInfoRef::from_der(&key_bytes)?;
    if spki.subject_public_key.raw_bytes().len() != 57 {
        return Err(anyhow::anyhow!("=> Invalid Ed448 public key"));
    }
    println!("{}", spki.subject_public_key.raw_bytes().len());
    let mut x_bytes = [0; 57];
    x_bytes.copy_from_slice(&spki.subject_public_key.raw_bytes());
    Ok(x_bytes)
}
#[cfg(feature = "rustcrypto")]
pub fn ed25519_public_to_ec_der(key_bytes: &[u8], for_dh: bool) -> Vec<u8> {
    use rsa::pkcs8::{der::Encode, AlgorithmIdentifierRef, ObjectIdentifier};
    let oid = if for_dh {
        ObjectIdentifier::new_unwrap("1.3.101.110")
    } else {
        ObjectIdentifier::new_unwrap("1.3.101.112")
    };
    let spki = SubjectPublicKeyInfoRef {
        algorithm: AlgorithmIdentifierRef {
            oid,
            parameters: None,
        },
        subject_public_key: BitStringRef::from_bytes(key_bytes).unwrap(),
    };
    spki.to_der().unwrap()
}
#[cfg(feature = "rustcrypto")]
pub fn ed25519_private_from_der(der: &[u8]) -> Result<[u8; 32], anyhow::Error> {
    use rsa::pkcs8::der::Decode;

    let pki: PrivateKeyInfoRef = PrivateKeyInfoRef::from_der(&der).unwrap();

    if pki.private_key.as_bytes().len() != 34 {
        bail!("Invalid x25519 private key length");
    }
    let mut x_bytes: [u8; 32] = [0; 32];
    x_bytes.copy_from_slice(&pki.private_key.as_bytes()[2..]);
    Ok(x_bytes)
}
#[cfg(feature = "rustcrypto")]
pub fn ed25519_private_to_ec_der(key_bytes: &[u8], for_dh: bool) -> Vec<u8> {
    use rsa::pkcs8::{
        der::{asn1::OctetString, Encode},
        AlgorithmIdentifierRef, ObjectIdentifier,
    };

    let octet_string = OctetString::new(key_bytes).unwrap().to_der().unwrap();
    let oid = if for_dh {
        ObjectIdentifier::new_unwrap("1.3.101.110")
    } else {
        ObjectIdentifier::new_unwrap("1.3.101.112")
    };
    let pki = PrivateKeyInfoRef::new(
        AlgorithmIdentifierRef {
            oid,
            parameters: None,
        },
        OctetStringRef::new(&octet_string).unwrap(),
    );
    pki.to_der().unwrap()
}
#[cfg(feature = "rustcrypto")]
pub fn ed448_public_to_ec_der(key_bytes: &[u8], for_dh: bool) -> Vec<u8> {
    use rsa::pkcs8::{der::Encode, AlgorithmIdentifierRef, ObjectIdentifier};
    let oid = if for_dh {
        ObjectIdentifier::new_unwrap("1.3.101.111")
    } else {
        ObjectIdentifier::new_unwrap("1.3.101.113")
    };
    let spki = SubjectPublicKeyInfoRef {
        algorithm: AlgorithmIdentifierRef {
            oid,
            parameters: None,
        },
        subject_public_key: BitStringRef::from_bytes(key_bytes).unwrap(),
    };
    spki.to_der().unwrap()
}
#[cfg(feature = "rustcrypto")]
pub fn x448_private_from_der(der: &[u8]) -> Result<[u8; 56], anyhow::Error> {
    use rsa::pkcs8::der::Decode;

    let pki: PrivateKeyInfoRef = PrivateKeyInfoRef::from_der(&der).unwrap();
    if pki.private_key.as_bytes().len() != 58 {
        bail!("Invalid x448 private key length [from der]");
    }
    let mut x_bytes: [u8; 56] = [0; 56];
    x_bytes.copy_from_slice(&pki.private_key.as_bytes()[2..]);
    Ok(x_bytes)
}
#[cfg(feature = "rustcrypto")]
pub fn ed448_private_from_der(der: &[u8]) -> Result<[u8; 57], anyhow::Error> {
    use rsa::pkcs8::der::Decode;

    let pki: PrivateKeyInfoRef = PrivateKeyInfoRef::from_der(&der).unwrap();
    if pki.private_key.as_bytes().len() != 59 {
        bail!("Invalid ed448 private key length");
    }
    let mut x_bytes: [u8; 57] = [0; 57];
    x_bytes.copy_from_slice(&pki.private_key.as_bytes()[2..]);
    Ok(x_bytes)
}
#[cfg(feature = "rustcrypto")]
pub fn ed448_private_to_ec_der(key_bytes: &[u8], for_dh: bool) -> Vec<u8> {
    use rsa::pkcs8::{
        der::{asn1::OctetString, Encode},
        AlgorithmIdentifierRef, ObjectIdentifier,
    };

    let octet_string = OctetString::new(key_bytes).unwrap().to_der().unwrap();
    let oid = if for_dh {
        ObjectIdentifier::new_unwrap("1.3.101.111")
    } else {
        ObjectIdentifier::new_unwrap("1.3.101.113")
    };
    println!("{key_bytes:?}");
    println!("{}", key_bytes.len());
    let pki = PrivateKeyInfoRef::new(
        AlgorithmIdentifierRef {
            oid,
            parameters: None,
        },
        OctetStringRef::new(&octet_string).unwrap(),
    );
    pki.to_der().unwrap()
}

#[cfg(feature = "rustcrypto")]
impl PrivateKey {
    pub fn public_key(&self) -> PublicKey {
        match self {
            PrivateKey::P256(key) => PublicKey::P256(key.public_key()),
            PrivateKey::P384(key) => PublicKey::P384(key.public_key()),
            PrivateKey::P521(key) => PublicKey::P521(key.public_key()),
            PrivateKey::K256(key) => PublicKey::K256(key.public_key()),
            PrivateKey::X25519(key) => PublicKey::X25519(x25519_dalek::PublicKey::from(key)),
            PrivateKey::X448(key) => PublicKey::X448(cx448::x448::PublicKey::from(key)),
            PrivateKey::Ed25519(key) => PublicKey::Ed25519(ed25519_dalek::VerifyingKey::from(key)),
            PrivateKey::Ed448(key) => PublicKey::Ed448(key.verifying_key()),
        }
    }
    pub fn secret_bytes(&self) -> Vec<u8> {
        match self {
            PrivateKey::P256(key) => key.to_bytes().to_vec(),
            PrivateKey::P384(key) => key.to_bytes().to_vec(),
            PrivateKey::P521(key) => key.to_bytes().to_vec(),
            PrivateKey::K256(key) => key.to_bytes().to_vec(),
            PrivateKey::X25519(key) => key.to_bytes().to_vec(),
            PrivateKey::X448(key) => key.as_bytes().to_vec(),
            PrivateKey::Ed25519(key) => key.to_bytes().to_vec(),
            PrivateKey::Ed448(key) => key.as_bytes().to_vec(),
        }
    }
    pub fn ec_key_der(&self) -> Result<Vec<u8>, anyhow::Error> {
        match self {
            PrivateKey::P256(key) => Ok(key.to_sec1_der()?.to_vec()),
            PrivateKey::P384(key) => Ok(key.to_sec1_der()?.to_vec()),
            PrivateKey::P521(key) => Ok(key.to_sec1_der()?.to_vec()),
            PrivateKey::K256(key) => Ok(key.to_sec1_der()?.to_vec()),
            PrivateKey::X25519(key) => Ok(ed25519_private_to_ec_der(key.as_bytes(), true)),
            PrivateKey::X448(key) => Ok(ed448_private_to_ec_der(key.as_bytes(), true)),
            PrivateKey::Ed25519(key) => Ok(ed25519_private_to_ec_der(key.as_bytes(), false)),
            PrivateKey::Ed448(key) => Ok(ed448_private_to_ec_der(key.as_bytes(), false)),
        }
    }
    pub fn ec_key_pem(&self) -> Result<String, anyhow::Error> {
        use k256::pkcs8::LineEnding;

        match self {
            PrivateKey::P256(key) => Ok(key.to_sec1_pem(LineEnding::CRLF).unwrap().to_string()),
            PrivateKey::P384(key) => Ok(key.to_sec1_pem(LineEnding::CRLF).unwrap().to_string()),
            PrivateKey::P521(key) => Ok(key.to_sec1_pem(LineEnding::CRLF).unwrap().to_string()),
            PrivateKey::K256(key) => Ok(key.to_sec1_pem(LineEnding::CRLF).unwrap().to_string()),
            PrivateKey::X25519(key) => {
                use pem::Pem;
                let key_bytes = ed25519_private_to_ec_der(key.as_bytes(), true);
                let pem = pem::encode(&Pem::new("PRIVATE KEY", key_bytes));
                Ok(pem)
            }
            PrivateKey::X448(key) => {
                use pem::Pem;
                let key_bytes = ed448_private_to_ec_der(key.as_bytes(), true);
                let pem = pem::encode(&Pem::new("PRIVATE KEY", key_bytes));
                Ok(pem)
            }
            PrivateKey::Ed25519(key) => {
                use pem::Pem;
                let key_bytes = ed25519_private_to_ec_der(key.as_bytes(), false);
                let pem = pem::encode(&Pem::new("PRIVATE KEY", key_bytes));
                Ok(pem)
            }
            PrivateKey::Ed448(key) => {
                use pem::Pem;
                let key_bytes = ed448_private_to_ec_der(key.as_bytes(), false);
                let pem = pem::encode(&Pem::new("PRIVATE KEY", key_bytes));
                Ok(pem)
            }
        }
    }
    pub fn ec_key_jwk(&self) -> Result<String, anyhow::Error> {
        match self {
            PrivateKey::P256(key) => Ok(key.to_jwk_string().to_string()),
            PrivateKey::P384(key) => Ok(key.to_jwk_string().to_string()),
            PrivateKey::P521(key) => Ok(key.to_jwk_string().to_string()),
            PrivateKey::K256(key) => Ok(key.to_jwk_string().to_string()),
            PrivateKey::X25519(_key) => todo!("JWK not implemented for x25519"),
            PrivateKey::X448(_key) => todo!("JWK not implemented for x448"),
            PrivateKey::Ed25519(_key) => todo!("JWK not implemented for ed25519"),
            PrivateKey::Ed448(_key) => todo!("JWK not implemented for ed448"),
        }
    }
    pub fn from_pkcs8_for_ec_curve(
        curve: EcCurve,
        pkcs8_der: &[u8],
    ) -> Result<Self, anyhow::Error> {
        Self::from_pkcs8(EcdhEsKeyType::Ec(curve), pkcs8_der)
    }
    pub fn from_pkcs8_for_ecx_curve(
        curve: EcxCurve,
        pkcs8_der: &[u8],
    ) -> Result<Self, anyhow::Error> {
        Self::from_pkcs8(EcdhEsKeyType::Ecx(curve), pkcs8_der)
    }
    pub fn from_pkcs8_for_ed_curve(
        curve: EdCurve,
        pkcs8_der: &[u8],
    ) -> Result<Self, anyhow::Error> {
        Ok(match curve {
            EdCurve::Ed25519 => PrivateKey::Ed25519(ed25519_dalek::SigningKey::from(
                ed25519_private_from_der(&pkcs8_der)?,
            )),
            EdCurve::Ed448 => PrivateKey::Ed448(cx448::SigningKey::from(
                cx448::SecretKey::from_slice(&ed448_private_from_der(&pkcs8_der)?),
            )),
        })
    }
    fn from_pkcs8(key_type: EcdhEsKeyType, pkcs8_der: &[u8]) -> Result<Self, anyhow::Error> {
        Ok(match key_type {
            EcdhEsKeyType::Ec(ec_curve) => match ec_curve {
                EcCurve::P256 => {
                    use p256::pkcs8::DecodePrivateKey;
                    PrivateKey::P256(p256::SecretKey::from_pkcs8_der(pkcs8_der)?)
                }
                EcCurve::P384 => {
                    use p384::pkcs8::DecodePrivateKey;
                    PrivateKey::P384(p384::SecretKey::from_pkcs8_der(pkcs8_der)?)
                }
                EcCurve::P521 => {
                    use p521::pkcs8::DecodePrivateKey;
                    PrivateKey::P521(p521::SecretKey::from_pkcs8_der(pkcs8_der)?)
                }
                EcCurve::Secp256k1 => {
                    use k256::pkcs8::DecodePrivateKey;
                    PrivateKey::K256(k256::SecretKey::from_pkcs8_der(pkcs8_der)?)
                }
            },
            EcdhEsKeyType::Ecx(ecx_curve) => match ecx_curve {
                EcxCurve::X25519 => PrivateKey::X25519(x25519_dalek::StaticSecret::from(
                    ed25519_private_from_der(&pkcs8_der)?,
                )),
                EcxCurve::X448 => PrivateKey::X448(
                    cx448::x448::Secret::from_bytes(&x448_private_from_der(&pkcs8_der)?).unwrap(),
                ),
            },
        })
    }

    pub fn derive_shared_secret(&self, public_key: PublicKey) -> Result<Vec<u8>, anyhow::Error> {
        use k256::elliptic_curve;
        match (self, public_key) {
            (PrivateKey::P256(secret_key), PublicKey::P256(public_key)) => {
                Ok(elliptic_curve::ecdh::diffie_hellman(
                    secret_key.to_nonzero_scalar(),
                    public_key.as_affine(),
                )
                .raw_secret_bytes()
                .to_vec())
            }
            (PrivateKey::P384(secret_key), PublicKey::P384(public_key)) => {
                Ok(elliptic_curve::ecdh::diffie_hellman(
                    secret_key.to_nonzero_scalar(),
                    public_key.as_affine(),
                )
                .raw_secret_bytes()
                .to_vec())
            }
            (PrivateKey::P521(secret_key), PublicKey::P521(public_key)) => {
                Ok(elliptic_curve::ecdh::diffie_hellman(
                    secret_key.to_nonzero_scalar(),
                    public_key.as_affine(),
                )
                .raw_secret_bytes()
                .to_vec())
            }
            (PrivateKey::K256(secret_key), PublicKey::K256(public_key)) => {
                Ok(elliptic_curve::ecdh::diffie_hellman(
                    secret_key.to_nonzero_scalar(),
                    public_key.as_affine(),
                )
                .raw_secret_bytes()
                .to_vec())
            }
            (PrivateKey::X25519(static_secret), PublicKey::X25519(public_key)) => Ok(static_secret
                .diffie_hellman(&public_key)
                .to_bytes()
                .to_vec()),
            (PrivateKey::X448(secret), PublicKey::X448(public_key)) => Ok(secret
                .to_diffie_hellman(&public_key)
                .unwrap()
                .as_bytes()
                .to_vec()),
            _ => {
                bail!("Public/Private key type mismatch")
            }
        }
    }
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        Ok(match self {
            PrivateKey::P256(secret_key) => {
                use p256::ecdsa::signature::SignerMut;
                let mut s: p256::ecdsa::SigningKey = secret_key.into();
                let signature: p256::ecdsa::Signature = s.sign(msg);
                signature.to_der().to_bytes().to_vec()
            }
            PrivateKey::P384(secret_key) => {
                use p384::ecdsa::signature::SignerMut;
                let mut s: p384::ecdsa::SigningKey = secret_key.into();
                let signature: p384::ecdsa::Signature = s.sign(msg);
                signature.to_der().to_bytes().to_vec()
            }
            PrivateKey::P521(secret_key) => {
                use p521::ecdsa::signature::SignerMut;
                let mut s: p521::ecdsa::SigningKey = p521::ecdsa::SigningKey::from_slice(
                    secret_key.to_nonzero_scalar().to_bytes().as_slice(),
                )?;
                let signature: p521::ecdsa::Signature = s.sign(msg);
                signature.to_der().to_bytes().to_vec()
            }
            PrivateKey::K256(secret_key) => {
                use k256::ecdsa::signature::Signer;
                let s: k256::ecdsa::SigningKey = secret_key.into();
                let signature: k256::ecdsa::Signature = s.sign(msg);
                signature.to_der().to_bytes().to_vec()
            }
            PrivateKey::X25519(_) => unimplemented!("x25519 is DH algorithm"),
            PrivateKey::X448(_) => unimplemented!("x448 is DH algorithm"),
            PrivateKey::Ed25519(signing_key) => {
                use ed25519_dalek::Signer;
                let signature: ed25519_dalek::Signature = signing_key.sign(msg);
                signature.to_bytes().to_vec()
            }
            PrivateKey::Ed448(signing_key) => {
                use cx448::crypto_signature::Signer;
                let signature: cx448::Signature = signing_key.sign(msg);
                let vk = signing_key.verifying_key();
                println!("vk1: {:?}", vk.as_bytes());
                signature.to_bytes().to_vec()
            }
        })
    }
    pub fn sign_prehashed(&self, digest: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        Ok(match self {
            PrivateKey::P256(secret_key) => {
                use p256::ecdsa::signature::hazmat::PrehashSigner;
                let s: p256::ecdsa::SigningKey = secret_key.into();
                let signature: p256::ecdsa::Signature = s.sign_prehash(digest)?;
                signature.to_der().to_bytes().to_vec()
            }
            PrivateKey::P384(secret_key) => {
                use p384::ecdsa::signature::hazmat::PrehashSigner;
                let s: p384::ecdsa::SigningKey = secret_key.into();
                let signature: p384::ecdsa::Signature = s.sign_prehash(digest)?;
                signature.to_der().to_bytes().to_vec()
            }
            PrivateKey::P521(secret_key) => {
                use p521::ecdsa::signature::hazmat::PrehashSigner;
                let s: p521::ecdsa::SigningKey = p521::ecdsa::SigningKey::from_slice(
                    secret_key.to_nonzero_scalar().to_bytes().as_slice(),
                )?;
                let signature: p521::ecdsa::Signature = s.sign_prehash(digest)?;
                signature.to_der().to_bytes().to_vec()
            }
            PrivateKey::K256(secret_key) => {
                use k256::ecdsa::signature::hazmat::PrehashSigner;
                let s: k256::ecdsa::SigningKey = secret_key.into();
                let signature: k256::ecdsa::Signature = s.sign_prehash(digest)?;
                signature.to_der().to_bytes().to_vec()
            }
            PrivateKey::X25519(_) => unimplemented!("x25519 is DH algorithm"),
            PrivateKey::X448(_) => unimplemented!("x448 is DH algorithm"),
            PrivateKey::Ed25519(signing_key) => {
                use ed25519_dalek::{Digest, DigestSigner};
                let signature: ed25519_dalek::Signature =
                    signing_key.sign_digest(|d: &mut ed25519_dalek::Sha512| d.update(digest));
                signature.to_bytes().to_vec()
            }
            PrivateKey::Ed448(_signing_key) => {
                // use cx448::crypto_signature::{
                //     digest::Digest, digest::FixedOutput, digest::HashMarker, DigestSigner,

                // };

                // let signature: cx448::Signature = signing_key
                //     .sign_digest::<cx448::crypto_signature::digest::Digest>(
                //     |d: &mut cx448::sha3::Sha3_512| d.update(digest),
                // );
                // let vk = signing_key.verifying_key();
                // println!("vk1: {:?}", vk.as_bytes());
                // signature.to_bytes().to_vec()
                unimplemented!("fucking annoying traits");
            }
        })
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
enum EcdhEsKeyType {
    Ec(EcCurve),
    Ecx(EcxCurve),
}

impl EcdhEsKeyType {
    fn key_type(&self) -> &str {
        match self {
            Self::Ec(_) => "EC",
            Self::Ecx(_) => "OKP",
        }
    }

    fn curve_name(&self) -> &str {
        match self {
            Self::Ec(val) => val.name(),
            Self::Ecx(val) => val.name(),
        }
    }
}

impl Display for EcdhEsKeyType {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.key_type())?;
        fmt.write_str("(")?;
        fmt.write_str(self.curve_name())?;
        fmt.write_str(")")?;
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum EcdhEsJweAlgorithm {
    /// Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF
    EcdhEs,
    /// ECDH-ES using Concat KDF and CEK wrapped with "A128KW"
    EcdhEsA128kw,
    /// ECDH-ES using Concat KDF and CEK wrapped with "A192KW"
    EcdhEsA192kw,
    /// ECDH-ES using Concat KDF and CEK wrapped with "A256KW"
    EcdhEsA256kw,
}

impl EcdhEsJweAlgorithm {
    /// Generate EC key pair for ECDH.
    pub fn generate_ec_key_pair(&self, curve: EcCurve) -> Result<EcKeyPair, JoseError> {
        let mut key_pair = EcKeyPair::generate(curve)?;
        key_pair.set_algorithm(Some(self.name()));
        Ok(key_pair)
    }

    /// Generate ECx key pair for ECDH.
    pub fn generate_ecx_key_pair(&self, curve: EcxCurve) -> Result<EcxKeyPair, JoseError> {
        let mut key_pair = EcxKeyPair::generate(curve)?;
        key_pair.set_algorithm(Some(self.name()));
        Ok(key_pair)
    }

    /// Create a EC key pair for ECDH from a private key that is a DER encoded PKCS#8 PrivateKeyInfo or ECPrivateKey.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo or ECPrivateKey.
    pub fn key_pair_from_ec_der(&self, input: impl AsRef<[u8]>) -> Result<EcKeyPair, JoseError> {
        let mut key_pair = EcKeyPair::from_der(input, None)?;
        key_pair.set_algorithm(Some(self.name()));
        Ok(key_pair)
    }

    /// Create a ECx key pair for ECDH from a private key that is a DER encoded PKCS#8 PrivateKeyInfo.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo.
    pub fn key_pair_from_ecx_der(&self, input: impl AsRef<[u8]>) -> Result<EcxKeyPair, JoseError> {
        let mut key_pair = EcxKeyPair::from_der(input)?;
        key_pair.set_algorithm(Some(self.name()));
        Ok(key_pair)
    }

    /// Create a EC key pair for ECDH from a private key of common or traditinal PEM format.
    ///
    /// Common PEM format is a DER and base64 encoded PKCS#8 PrivateKeyInfo
    /// that surrounded by "-----BEGIN/END PRIVATE KEY----".
    ///
    /// Traditional PEM format is a DER and base64 encoded ECPrivateKey
    /// that surrounded by "-----BEGIN/END EC PRIVATE KEY----".
    ///
    /// # Arguments
    /// * `input` - A private key of common or traditinal PEM format.
    pub fn key_pair_from_ec_pem(&self, input: impl AsRef<[u8]>) -> Result<EcKeyPair, JoseError> {
        let mut key_pair = EcKeyPair::from_pem(input.as_ref(), None)?;
        key_pair.set_algorithm(Some(self.name()));
        Ok(key_pair)
    }

    /// Create a ECx key pair for ECDH from a private key of common or traditinal PEM format.
    ///
    /// Common PEM format is a DER and base64 encoded PKCS#8 PrivateKeyInfo
    /// that surrounded by "-----BEGIN/END PRIVATE KEY----".
    ///
    /// Traditional PEM format is a DER and base64 encoded ECPrivateKey
    /// that surrounded by "-----BEGIN/END X25519/X448 PRIVATE KEY----".
    ///
    /// # Arguments
    /// * `input` - A private key of common or traditinal PEM format.
    pub fn key_pair_from_ecx_pem(&self, input: impl AsRef<[u8]>) -> Result<EcxKeyPair, JoseError> {
        let mut key_pair = EcxKeyPair::from_pem(input.as_ref())?;
        key_pair.set_algorithm(Some(self.name()));
        Ok(key_pair)
    }

    pub fn encrypter_from_der(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<EcdhEsJweEncrypter, JoseError> {
        (|| -> anyhow::Result<EcdhEsJweEncrypter> {
            let (spki, key_type) = match Self::detect_pkcs8(input.as_ref(), true) {
                Some(val) => (input.as_ref(), val),
                None => bail!("The public key must be wrapped by SubjectPublicKeyInfo."),
            };
            #[cfg(feature = "openssl")]
            let public_key = PKey::public_key_from_der(spki)?;
            #[cfg(feature = "rustcrypto")]
            let public_key = PublicKey::from_pkcs8_der(key_type, spki)?;

            Ok(EcdhEsJweEncrypter {
                algorithm: self.clone(),
                public_key,
                key_type,
                key_id: None,
                agreement_partyuinfo: None,
                agreement_partyvinfo: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn encrypter_from_pem(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<EcdhEsJweEncrypter, JoseError> {
        (|| -> anyhow::Result<EcdhEsJweEncrypter> {
            let (alg, data) = util::parse_pem(input.as_ref())?;

            let (spki, key_type) = match alg.as_str() {
                "PUBLIC KEY" => match Self::detect_pkcs8(&data, true) {
                    Some(val) => (data.as_slice(), val),
                    None => bail!("PEM contents is expected SubjectPublicKeyInfo wrapped key."),
                },
                alg => bail!("Inappropriate algorithm: {}", alg),
            };
            #[cfg(feature = "openssl")]
            let public_key = PKey::public_key_from_der(spki)?;
            #[cfg(feature = "rustcrypto")]
            let public_key = PublicKey::from_pkcs8_der(key_type, spki)?;

            Ok(EcdhEsJweEncrypter {
                algorithm: self.clone(),
                public_key,
                key_type,
                key_id: None,
                agreement_partyuinfo: None,
                agreement_partyvinfo: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

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
            if !jwk.is_for_key_operation("deriveKey") {
                bail!("A parameter key_ops must contains deriveKey.");
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }
            let (public_key, key_type) = match jwk.parameter("crv") {
                Some(Value::String(val)) => match key_type {
                    "EC" => {
                        let curve = match val.as_str() {
                            "P-256" => EcCurve::P256,
                            "P-384" => EcCurve::P384,
                            "P-521" => EcCurve::P521,
                            "secp256k1" => EcCurve::Secp256k1,
                            val => bail!("EC key doesn't support the curve algorithm: {}", val),
                        };
                        let x = match jwk.parameter("x") {
                            Some(Value::String(val)) => util::decode_base64_urlsafe_no_pad(val)?,
                            Some(_) => bail!("A parameter x must be a string."),
                            None => bail!("A parameter x is required."),
                        };
                        let y = match jwk.parameter("y") {
                            Some(Value::String(val)) => util::decode_base64_urlsafe_no_pad(val)?,
                            Some(_) => bail!("A parameter y must be a string."),
                            None => bail!("A parameter y is required."),
                        };

                        let mut vec = Vec::with_capacity(1 + x.len() + y.len());
                        vec.push(0x04);
                        vec.extend_from_slice(&x);
                        vec.extend_from_slice(&y);
                        // #[cfg(feature = "openssl")]
                        let pkcs8 = EcKeyPair::to_pkcs8(&vec, true, curve);
                        #[cfg(feature = "openssl")]
                        let public_key = PKey::public_key_from_der(&pkcs8)?;
                        #[cfg(feature = "rustcrypto")]
                        let public_key =
                            PublicKey::from_pkcs8_der(EcdhEsKeyType::Ec(curve), &pkcs8)?;
                        (public_key, EcdhEsKeyType::Ec(curve))
                    }
                    "OKP" => {
                        let curve = match val.as_str() {
                            "X25519" => EcxCurve::X25519,
                            "X448" => EcxCurve::X448,
                            val => bail!("OKP key doesn't support the curve algorithm: {}", val),
                        };
                        let x = match jwk.parameter("x") {
                            Some(Value::String(val)) => util::decode_base64_urlsafe_no_pad(val)?,
                            Some(_) => bail!("A parameter x must be a string."),
                            None => bail!("A parameter x is required."),
                        };

                        #[cfg(feature = "openssl")]
                        let pkcs8 = EcxKeyPair::to_pkcs8(&x, true, curve);
                        #[cfg(feature = "openssl")]
                        let public_key = PKey::public_key_from_der(&pkcs8)?;
                        #[cfg(feature = "rustcrypto")]
                        let public_key = match curve {
                            EcxCurve::X25519 => {
                                if x.len() != 32 {
                                    bail!("-> Invalid x25519 public key length");
                                }
                                let mut x_bytes: [u8; 32] = [0; 32];
                                x_bytes.copy_from_slice(&x);
                                let public_key = x25519_dalek::PublicKey::from(x_bytes);
                                PublicKey::X25519(public_key)
                            }
                            EcxCurve::X448 => {
                                if let Some(public_key) = cx448::x448::PublicKey::from_bytes(&x) {
                                    PublicKey::X448(public_key)
                                } else {
                                    bail!("Invalid x448 Key");
                                }
                            }
                        };
                        (public_key, EcdhEsKeyType::Ecx(curve))
                    }
                    _ => unreachable!(),
                },
                Some(_) => bail!("A parameter crv must be a string."),
                None => bail!("A parameter crv is required."),
            };
            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(EcdhEsJweEncrypter {
                algorithm: self.clone(),
                key_type,
                public_key,
                key_id,
                agreement_partyuinfo: None,
                agreement_partyvinfo: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn decrypter_from_der(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<EcdhEsJweDecrypter, JoseError> {
        (|| -> anyhow::Result<EcdhEsJweDecrypter> {
            let pkcs8_der_vec;
            let (pkcs8_der, key_type) = match Self::detect_pkcs8(input.as_ref(), false) {
                Some(val) => (input.as_ref(), val),
                None => match EcKeyPair::detect_ec_curve(input.as_ref()) {
                    Some(val) => {
                        pkcs8_der_vec = EcKeyPair::to_pkcs8(input.as_ref(), false, val);
                        (pkcs8_der_vec.as_slice(), EcdhEsKeyType::Ec(val))
                    }
                    None => bail!("A curve name cannot be determined."),
                },
            };
            #[cfg(feature = "openssl")]
            let private_key = PKey::private_key_from_der(pkcs8_der)?;
            #[cfg(feature = "rustcrypto")]
            let private_key = match key_type {
                EcdhEsKeyType::Ec(ec_curve) => match ec_curve {
                    EcCurve::P256 => {
                        use p256::pkcs8::DecodePrivateKey;
                        PrivateKey::P256(p256::SecretKey::from_pkcs8_der(&pkcs8_der).unwrap())
                    }
                    EcCurve::P384 => {
                        use p384::pkcs8::DecodePrivateKey;
                        PrivateKey::P384(p384::SecretKey::from_pkcs8_der(&pkcs8_der).unwrap())
                    }
                    EcCurve::P521 => {
                        use p521::pkcs8::DecodePrivateKey;
                        PrivateKey::P521(p521::SecretKey::from_pkcs8_der(&pkcs8_der).unwrap())
                    }
                    EcCurve::Secp256k1 => {
                        use k256::pkcs8::DecodePrivateKey;
                        PrivateKey::K256(k256::SecretKey::from_pkcs8_der(&pkcs8_der).unwrap())
                    }
                },
                EcdhEsKeyType::Ecx(ecx_curve) => match ecx_curve {
                    EcxCurve::X25519 => PrivateKey::X25519(x25519_dalek::StaticSecret::from(
                        ed25519_private_from_der(&pkcs8_der)?,
                    )),
                    EcxCurve::X448 => PrivateKey::X448(
                        cx448::x448::Secret::from_bytes(&x448_private_from_der(&pkcs8_der)?)
                            .unwrap(),
                    ),
                },
            };

            Ok(EcdhEsJweDecrypter {
                algorithm: self.clone(),
                private_key,
                key_type,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn decrypter_from_pem(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<EcdhEsJweDecrypter, JoseError> {
        (|| -> anyhow::Result<EcdhEsJweDecrypter> {
            let (alg, data) = util::parse_pem(input.as_ref())?;

            let pkcs8_der_vec;
            let (pkcs8_der, key_type) = match alg.as_str() {
                "PRIVATE KEY" => match Self::detect_pkcs8(data.as_slice(), false) {
                    Some(val) => (data.as_slice(), val),
                    None => bail!("PEM contents is expected PKCS#8 wrapped key."),
                },
                "EC PRIVATE KEY" => match EcKeyPair::detect_ec_curve(data.as_slice()) {
                    Some(val) => {
                        pkcs8_der_vec = EcKeyPair::to_pkcs8(data.as_slice(), false, val);
                        (pkcs8_der_vec.as_slice(), EcdhEsKeyType::Ec(val))
                    }
                    None => bail!("A curve name cannot be determined."),
                },
                "X25519 PRIVATE KEY" => match Self::detect_pkcs8(data.as_slice(), false) {
                    Some(val @ EcdhEsKeyType::Ecx(EcxCurve::X25519)) => (data.as_slice(), val),
                    Some(val) => bail!("The curve name is mismatched: {}", val),
                    None => bail!("PEM contents is expected PKCS#8 wrapped key."),
                },
                "X448 PRIVATE KEY" => match Self::detect_pkcs8(data.as_slice(), false) {
                    Some(val @ EcdhEsKeyType::Ecx(EcxCurve::X448)) => (data.as_slice(), val),
                    Some(val) => bail!("The curve name is mismatched: {}", val),
                    None => bail!("PEM contents is expected PKCS#8 wrapped key."),
                },
                alg => bail!("Inappropriate algorithm: {}", alg),
            };
            #[cfg(feature = "openssl")]
            let private_key = PKey::private_key_from_der(pkcs8_der)?;
            #[cfg(feature = "rustcrypto")]
            let private_key = PrivateKey::from_pkcs8(key_type, pkcs8_der)?;

            Ok(EcdhEsJweDecrypter {
                algorithm: self.clone(),
                private_key,
                key_type,
                key_id: None,
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
            if !jwk.is_for_key_operation("deriveKey") {
                bail!("A parameter key_ops must contains deriveKey.");
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }
            let (private_key, key_type) = match jwk.parameter("crv") {
                Some(Value::String(val)) => match key_type {
                    "EC" => {
                        let curve = match val.as_str() {
                            "P-256" => EcCurve::P256,
                            "P-384" => EcCurve::P384,
                            "P-521" => EcCurve::P521,
                            "secp256k1" => EcCurve::Secp256k1,
                            val => bail!("EC key doesn't support the curve algorithm: {}", val),
                        };
                        match jwk.curve() {
                            Some(val) if val == curve.name() => {}
                            Some(val) => {
                                bail!("A parameter crv must be {} but {}", self.name(), val)
                            }
                            None => bail!("A parameter crv is required."),
                        }
                        let key_pair = EcKeyPair::from_jwk(&jwk)?;
                        let private_key = key_pair.into_private_key();

                        (private_key, EcdhEsKeyType::Ec(curve))
                    }
                    "OKP" => {
                        let curve = match val.as_str() {
                            "X25519" => EcxCurve::X25519,
                            "X448" => EcxCurve::X448,
                            val => bail!("OKP key doesn't support the curve algorithm: {}", val),
                        };
                        match jwk.curve() {
                            Some(val) if val == curve.name() => {}
                            Some(val) => {
                                bail!("A parameter crv must be {} but {}", self.name(), val)
                            }
                            None => bail!("A parameter crv is required."),
                        }
                        let key_pair = EcxKeyPair::from_jwk(&jwk)?;
                        let private_key = key_pair.into_private_key();

                        (private_key, EcdhEsKeyType::Ecx(curve))
                    }
                    _ => unreachable!(),
                },
                Some(_) => bail!("A parameter crv must be a string."),
                None => bail!("A parameter crv is required."),
            };
            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(EcdhEsJweDecrypter {
                algorithm: self.clone(),
                private_key,
                key_type,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn key_len(&self) -> usize {
        match self {
            Self::EcdhEsA128kw => 16,
            Self::EcdhEsA192kw => 24,
            Self::EcdhEsA256kw => 32,
            _ => unreachable!(),
        }
    }

    fn detect_pkcs8(input: &[u8], is_public: bool) -> Option<EcdhEsKeyType> {
        let key_type;
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
                            if val == *OID_X25519 {
                                return Some(EcdhEsKeyType::Ecx(EcxCurve::X25519));
                            } else if val == *OID_X448 {
                                return Some(EcdhEsKeyType::Ecx(EcxCurve::X448));
                            } else if val != *OID_ID_EC_PUBLIC_KEY {
                                return None;
                            }
                        }
                        _ => return None,
                    },
                    _ => return None,
                }

                key_type = match reader.next() {
                    Ok(Some(DerType::ObjectIdentifier)) => match reader.to_object_identifier() {
                        Ok(val) if val == *OID_PRIME256V1 => EcdhEsKeyType::Ec(EcCurve::P256),
                        Ok(val) if val == *OID_SECP384R1 => EcdhEsKeyType::Ec(EcCurve::P384),
                        Ok(val) if val == *OID_SECP521R1 => EcdhEsKeyType::Ec(EcCurve::P521),
                        Ok(val) if val == *OID_SECP256K1 => EcdhEsKeyType::Ec(EcCurve::Secp256k1),
                        _ => return None,
                    },
                    _ => return None,
                }
            }
        }

        Some(key_type)
    }

    fn concat_kdf(
        &self,
        alg: &str,
        shared_key_len: usize,
        derived_key: &[u8],
        apu: Option<&[u8]>,
        apv: Option<&[u8]>,
    ) -> anyhow::Result<Vec<u8>> {
        use sha2::{Digest, Sha256};
        let shared_key_len_bytes = ((shared_key_len * 8) as u32).to_be_bytes();
        let alg_len_bytes = (alg.len() as u32).to_be_bytes();
        let apu_len_bytes = (match apu {
            Some(val) => val.len(),
            None => 0,
        } as u32)
            .to_be_bytes();
        let apv_len_bytes = (match apv {
            Some(val) => val.len(),
            None => 0,
        } as u32)
            .to_be_bytes();

        let mut shared_key = Vec::new();
        #[cfg(feature = "openssl")]
        let md = MessageDigest::sha256();
        #[cfg(feature = "openssl")]
        let digest_size = md.size();
        #[cfg(feature = "rustcrypto")]
        let digest_size = Sha256::output_size();
        let count = util::ceiling(shared_key_len, digest_size);
        for i in 0..count {
            #[cfg(feature = "openssl")]
            let mut hasher = Hasher::new(md)?;
            #[cfg(feature = "rustcrypto")]
            let mut hasher = Sha256::new();
            //TODO: can we find a way to share the code? (openssl returns an error, sha2 not)
            #[cfg(feature = "openssl")]
            {
                hasher.update(&((i + 1) as u32).to_be_bytes())?;
                hasher.update(&derived_key)?;
                hasher.update(&alg_len_bytes)?;
                hasher.update(alg.as_bytes())?;
                hasher.update(&apu_len_bytes)?;
            }
            #[cfg(feature = "rustcrypto")]
            {
                hasher.update(&((i + 1) as u32).to_be_bytes());
                hasher.update(&derived_key);
                hasher.update(&alg_len_bytes);
                hasher.update(alg.as_bytes());
                hasher.update(&apu_len_bytes);
            }

            if let Some(val) = apu {
                #[cfg(feature = "rustcrypto")]
                hasher.update(val);
                #[cfg(feature = "openssl")]
                hasher.update(val)?;
            }
            #[cfg(feature = "rustcrypto")]
            hasher.update(&apv_len_bytes);
            #[cfg(feature = "openssl")]
            hasher.update(&apv_len_bytes)?;

            if let Some(val) = apv {
                #[cfg(feature = "rustcrypto")]
                hasher.update(val);
                #[cfg(feature = "openssl")]
                hasher.update(val)?;
            }
            #[cfg(feature = "rustcrypto")]
            hasher.update(&shared_key_len_bytes);
            #[cfg(feature = "openssl")]
            hasher.update(&shared_key_len_bytes)?;

            #[cfg(feature = "openssl")]
            let digest = hasher.finish()?;
            #[cfg(feature = "rustcrypto")]
            let digest = hasher.finalize();
            shared_key.extend(digest.to_vec());
        }

        if shared_key.len() > shared_key_len {
            shared_key.truncate(shared_key_len);
        } else if shared_key.len() < shared_key_len {
            unreachable!();
        }

        Ok(shared_key)
    }
}

impl JweAlgorithm for EcdhEsJweAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::EcdhEs => "ECDH-ES",
            Self::EcdhEsA128kw => "ECDH-ES+A128KW",
            Self::EcdhEsA192kw => "ECDH-ES+A192KW",
            Self::EcdhEsA256kw => "ECDH-ES+A256KW",
        }
    }

    fn box_clone(&self) -> Box<dyn JweAlgorithm> {
        Box::new(self.clone())
    }
}

impl Display for EcdhEsJweAlgorithm {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for EcdhEsJweAlgorithm {
    type Target = dyn JweAlgorithm;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct EcdhEsJweEncrypter {
    algorithm: EcdhEsJweAlgorithm,
    key_type: EcdhEsKeyType,
    #[cfg(feature = "openssl")]
    public_key: PKey<Public>,
    #[cfg(feature = "rustcrypto")]
    public_key: PublicKey,
    agreement_partyuinfo: Option<Vec<u8>>,
    agreement_partyvinfo: Option<Vec<u8>>,
    key_id: Option<String>,
}

impl EcdhEsJweEncrypter {
    pub fn set_agreement_partyuinfo(&mut self, value: impl Into<Vec<u8>>) {
        self.agreement_partyuinfo = Some(value.into());
    }

    pub fn remove_agreement_partyuinfo(&mut self) {
        self.agreement_partyuinfo = None;
    }

    pub fn set_agreement_partyvinfo(&mut self, value: impl Into<Vec<u8>>) {
        self.agreement_partyvinfo = Some(value.into());
    }

    pub fn remove_agreement_partyvinfo(&mut self) {
        self.agreement_partyvinfo = None;
    }

    pub fn set_key_id(&mut self, value: impl Into<String>) {
        self.key_id = Some(value.into());
    }

    pub fn remove_key_id(&mut self) {
        self.key_id = None;
    }

    fn compute_shared_key(
        &self,
        header: &mut JweHeader,
        alg: &str,
        key_len: usize,
    ) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let apu_vec;
            let apu = match header.claim("apu") {
                Some(Value::String(val)) => {
                    apu_vec = util::decode_base64_urlsafe_no_pad(val)?;
                    Some(apu_vec.as_slice())
                }
                Some(_) => bail!("The apu header claim must be string."),
                None => match &self.agreement_partyuinfo {
                    Some(val) => {
                        let apu_b64 = util::encode_base64_urlsafe_nopad(val);
                        header.set_claim("apu", Some(Value::String(apu_b64)))?;
                        Some(val.as_slice())
                    }
                    None => None,
                },
            };
            let apv_vec;
            let apv = match header.claim("apv") {
                Some(Value::String(val)) => {
                    apv_vec = util::decode_base64_urlsafe_no_pad(val)?;
                    Some(apv_vec.as_slice())
                }
                Some(_) => bail!("The apv header claim must be string."),
                None => match &self.agreement_partyvinfo {
                    Some(val) => {
                        let apv_b64 = util::encode_base64_urlsafe_nopad(val);
                        header.set_claim("apv", Some(Value::String(apv_b64)))?;
                        Some(val.as_slice())
                    }
                    None => None,
                },
            };

            let mut map = Map::new();
            map.insert(
                "kty".to_string(),
                Value::String(self.key_type.key_type().to_string()),
            );
            map.insert(
                "crv".to_string(),
                Value::String(self.key_type.curve_name().to_string()),
            );
            let private_key = match self.key_type {
                EcdhEsKeyType::Ec(curve) => {
                    let key_pair = EcKeyPair::generate(curve)?;
                    let mut jwk: Map<String, Value> = key_pair.to_jwk_public_key().into();

                    match jwk.remove("x") {
                        Some(val) => {
                            map.insert("x".to_string(), val);
                        }
                        None => unreachable!(),
                    }
                    match jwk.remove("y") {
                        Some(val) => {
                            map.insert("y".to_string(), val);
                        }
                        None => unreachable!(),
                    }

                    key_pair.into_private_key()
                }
                EcdhEsKeyType::Ecx(curve) => {
                    let key_pair = EcxKeyPair::generate(curve)?;
                    let mut jwk: Map<String, Value> = key_pair.to_jwk_public_key().into();

                    match jwk.remove("x") {
                        Some(val) => {
                            map.insert("x".to_string(), val);
                        }
                        None => unreachable!(),
                    }

                    key_pair.into_private_key()
                }
            };

            header.set_claim("epk", Some(Value::Object(map)))?;

            #[cfg(feature = "openssl")]
            let mut deriver = Deriver::new(&private_key)?;
            #[cfg(feature = "openssl")]
            deriver.set_peer(&self.public_key)?;
            #[cfg(feature = "openssl")]
            let derived_key = deriver.derive_to_vec()?;

            #[cfg(feature = "rustcrypto")]
            let derived_key = private_key.derive_shared_secret(self.public_key)?;

            let shared_key = self.algorithm.concat_kdf(
                alg,
                key_len,
                &derived_key,
                apu.as_deref(),
                apv.as_deref(),
            )?;

            Ok(shared_key)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidKeyFormat(err),
        })
    }
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

    fn compute_content_encryption_key<'a>(
        &'a self,
        cencryption: &dyn JweContentEncryption,
        _merged: &JweHeader,
        header: &mut JweHeader,
    ) -> Result<Option<Cow<'a, [u8]>>, JoseError> {
        if let EcdhEsJweAlgorithm::EcdhEs = self.algorithm {
            let shared_key =
                self.compute_shared_key(header, cencryption.name(), cencryption.key_len())?;
            Ok(Some(Cow::Owned(shared_key)))
        } else {
            Ok(None)
        }
    }

    fn encrypt(
        &self,
        key: &[u8],
        _merged: &JweHeader,
        header: &mut JweHeader,
    ) -> Result<Option<Vec<u8>>, JoseError> {
        (|| -> anyhow::Result<Option<Vec<u8>>> {
            if let EcdhEsJweAlgorithm::EcdhEs = self.algorithm {
                Ok(None)
            } else {
                let shared_key = self.compute_shared_key(
                    header,
                    self.algorithm().name(),
                    self.algorithm.key_len(),
                )?;
                let aes = match AesKey::new_encrypt(&shared_key) {
                    Ok(val) => val,
                    Err(_) => bail!("Failed to set encrypt key."),
                };

                let mut encrypted_key = vec![0; key.len() + 8];
                match aes::wrap_key(&aes, None, &mut encrypted_key, &key) {
                    #[allow(unused)]
                    Ok(len) =>
                    {
                        #[cfg(feature = "openssl")]
                        if len < encrypted_key.len() {
                            encrypted_key.truncate(len);
                        }
                    }
                    Err(_) => bail!("Failed to wrap key."),
                }

                Ok(Some(encrypted_key))
            }
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidKeyFormat(err),
        })
    }

    fn box_clone(&self) -> Box<dyn JweEncrypter> {
        Box::new(self.clone())
    }
}

impl Deref for EcdhEsJweEncrypter {
    type Target = dyn JweEncrypter;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct EcdhEsJweDecrypter {
    algorithm: EcdhEsJweAlgorithm,
    #[cfg(feature = "openssl")]
    private_key: PKey<Private>,
    #[cfg(feature = "rustcrypto")]
    private_key: PrivateKey,
    key_type: EcdhEsKeyType,
    key_id: Option<String>,
}

impl EcdhEsJweDecrypter {
    pub fn set_key_id(&mut self, value: impl Into<String>) {
        self.key_id = Some(value.into());
    }

    pub fn remove_key_id(&mut self) {
        self.key_id = None;
    }
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

    fn decrypt<'a>(
        &'a self,
        encrypted_key: Option<&[u8]>,
        cencryption: &dyn JweContentEncryption,
        header: &JweHeader,
    ) -> Result<Cow<'a, [u8]>, JoseError> {
        (|| -> anyhow::Result<Cow<[u8]>> {
            match &self.algorithm {
                EcdhEsJweAlgorithm::EcdhEs => {
                    if encrypted_key.is_some() {
                        bail!("The encrypted_key must be empty.");
                    }
                }
                _ => {
                    if encrypted_key.is_none() {
                        bail!("A encrypted_key is required.");
                    }
                }
            }

            let apu = match header.claim("apu") {
                Some(Value::String(val)) => {
                    let apu = util::decode_base64_urlsafe_no_pad(val)?;
                    Some(apu)
                }
                Some(_) => bail!("The apu header claim must be string."),
                None => None,
            };
            let apv = match header.claim("apv") {
                Some(Value::String(val)) => {
                    let apv = util::decode_base64_urlsafe_no_pad(val)?;
                    Some(apv)
                }
                Some(_) => bail!("The apv header claim must be string."),
                None => None,
            };

            let public_key = match header.claim("epk") {
                Some(Value::Object(map)) => {
                    match map.get("kty") {
                        Some(Value::String(val)) => {
                            if val != self.key_type.key_type() {
                                bail!("The kty parameter in epk header claim is invalid: {}", val);
                            }
                        }
                        Some(_) => bail!("The kty parameter in epk header claim must be a string."),
                        None => bail!("The kty parameter in epk header claim is required."),
                    }

                    match map.get("crv") {
                        Some(Value::String(val)) => {
                            if val != self.key_type.curve_name() {
                                bail!("The crv parameter in epk header claim is invalid: {}", val);
                            }
                        }
                        Some(_) => bail!("The crv parameter in epk header claim must be a string."),
                        None => bail!("The crv parameter in epk header claim is required."),
                    }

                    match &self.key_type {
                        EcdhEsKeyType::Ec(curve) => {
                            let x = match map.get("x") {
                                Some(Value::String(val)) => {
                                    util::decode_base64_urlsafe_no_pad(val)?
                                }
                                Some(_) => {
                                    bail!("The x parameter in epk header claim must be a string.")
                                }
                                None => bail!("The x parameter in epk header claim is required."),
                            };
                            let y = match map.get("y") {
                                Some(Value::String(val)) => {
                                    util::decode_base64_urlsafe_no_pad(val)?
                                }
                                Some(_) => {
                                    bail!("The x parameter in epk header claim must be a string.")
                                }
                                None => bail!("The x parameter in epk header claim is required."),
                            };

                            let mut vec = Vec::with_capacity(1 + x.len() + y.len());
                            vec.push(0x04);
                            vec.extend_from_slice(&x);
                            vec.extend_from_slice(&y);

                            let pkcs8 = EcKeyPair::to_pkcs8(&vec, true, *curve);
                            #[cfg(feature = "openssl")]
                            let result = PKey::public_key_from_der(&pkcs8)?;
                            #[cfg(feature = "rustcrypto")]
                            let result = PublicKey::from_pkcs8_der(self.key_type, &pkcs8)?;
                            result
                        }
                        EcdhEsKeyType::Ecx(curve) => {
                            let x = match map.get("x") {
                                Some(Value::String(val)) => {
                                    util::decode_base64_urlsafe_no_pad(val)?
                                }
                                Some(_) => {
                                    bail!("The x parameter in epk header claim must be a string.")
                                }
                                None => bail!("The x parameter in epk header claim is required."),
                            };

                            let pkcs8 = EcxKeyPair::to_pkcs8(&x, true, *curve);
                            #[cfg(feature = "openssl")]
                            let result = PKey::public_key_from_der(&pkcs8)?;
                            #[cfg(feature = "rustcrypto")]
                            let result = PublicKey::from_pkcs8_der(self.key_type, &pkcs8)?;
                            result
                        }
                    }
                }
                Some(_) => bail!("The epk header claim must be object."),
                None => bail!("This algorithm must have epk header claim."),
            };

            #[cfg(feature = "openssl")]
            let mut deriver = Deriver::new(&self.private_key)?;
            #[cfg(feature = "openssl")]
            deriver.set_peer(&public_key)?;
            #[cfg(feature = "openssl")]
            let derived_key = deriver.derive_to_vec()?;

            #[cfg(feature = "rustcrypto")]
            let derived_key = self.private_key.derive_shared_secret(public_key)?;

            // concat KDF
            if let EcdhEsJweAlgorithm::EcdhEs = self.algorithm {
                let shared_key = self.algorithm.concat_kdf(
                    cencryption.name(),
                    cencryption.key_len(),
                    &derived_key,
                    apu.as_deref(),
                    apv.as_deref(),
                )?;
                Ok(Cow::Owned(shared_key))
            } else {
                let shared_key = self.algorithm.concat_kdf(
                    self.algorithm.name(),
                    self.algorithm.key_len(),
                    &derived_key,
                    apu.as_deref(),
                    apv.as_deref(),
                )?;

                let aes = match AesKey::new_decrypt(&shared_key) {
                    Ok(val) => val,
                    Err(_) => bail!("Failed to set encrypt key."),
                };

                let encrypted_key = match encrypted_key {
                    Some(val) => val,
                    None => unreachable!(),
                };

                let mut key = vec![0; encrypted_key.len() - 8];
                match aes::unwrap_key(&aes, None, &mut key, &encrypted_key) {
                    #[allow(unused)]
                    Ok(len) =>
                    {
                        #[cfg(feature = "openssl")]
                        if len < key.len() {
                            key.truncate(len);
                        }
                    }
                    Err(_) => bail!("Failed to unwrap key."),
                };

                Ok(Cow::Owned(key))
            }
        })()
        .map_err(|err| JoseError::InvalidJweFormat(err))
    }

    fn box_clone(&self) -> Box<dyn JweDecrypter> {
        Box::new(self.clone())
    }
}

impl Deref for EcdhEsJweDecrypter {
    type Target = dyn JweDecrypter;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use std::borrow::Cow;
    use std::fs;
    use std::path::PathBuf;

    use super::{EcdhEsJweAlgorithm, EcdhEsKeyType};
    use crate::jwe::enc::aescbc_hmac::AescbcHmacJweEncryption;
    use crate::jwe::enc::aesgcm::AesgcmJweEncryption;
    use crate::jwe::JweHeader;
    use crate::jwk::alg::{ec::EcCurve, ecx::EcxCurve};
    use crate::jwk::Jwk;
    use crate::util;

    #[test]
    fn encrypt_and_decrypt_ecdh_es_with_pkcs8_der() -> Result<()> {
        let enc = AescbcHmacJweEncryption::A128cbcHs256;

        for alg in vec![
            EcdhEsJweAlgorithm::EcdhEs,
            EcdhEsJweAlgorithm::EcdhEsA128kw,
            EcdhEsJweAlgorithm::EcdhEsA192kw,
            EcdhEsJweAlgorithm::EcdhEsA256kw,
        ] {
            for key in vec![
                EcdhEsKeyType::Ec(EcCurve::P256),
                EcdhEsKeyType::Ec(EcCurve::P384),
                EcdhEsKeyType::Ec(EcCurve::P521),
                EcdhEsKeyType::Ec(EcCurve::Secp256k1),
                EcdhEsKeyType::Ecx(EcxCurve::X25519),
                EcdhEsKeyType::Ecx(EcxCurve::X448),
            ] {
                let private_key = load_file(match key {
                    EcdhEsKeyType::Ec(EcCurve::P256) => "der/EC_P-256_pkcs8_private.der",
                    EcdhEsKeyType::Ec(EcCurve::P384) => "der/EC_P-384_pkcs8_private.der",
                    EcdhEsKeyType::Ec(EcCurve::P521) => "der/EC_P-521_pkcs8_private.der",
                    EcdhEsKeyType::Ec(EcCurve::Secp256k1) => "der/EC_secp256k1_pkcs8_private.der",
                    EcdhEsKeyType::Ecx(EcxCurve::X25519) => "der/X25519_pkcs8_private.der",
                    EcdhEsKeyType::Ecx(EcxCurve::X448) => "der/X448_pkcs8_private.der",
                })?;

                let public_key = load_file(match key {
                    EcdhEsKeyType::Ec(EcCurve::P256) => "der/EC_P-256_spki_public.der",
                    EcdhEsKeyType::Ec(EcCurve::P384) => "der/EC_P-384_spki_public.der",
                    EcdhEsKeyType::Ec(EcCurve::P521) => "der/EC_P-521_spki_public.der",
                    EcdhEsKeyType::Ec(EcCurve::Secp256k1) => "der/EC_secp256k1_spki_public.der",
                    EcdhEsKeyType::Ecx(EcxCurve::X25519) => "der/X25519_spki_public.der",
                    EcdhEsKeyType::Ecx(EcxCurve::X448) => "der/X448_spki_public.der",
                })?;

                let mut header = JweHeader::new();
                header.set_content_encryption(enc.name());

                let encrypter = alg.encrypter_from_der(&public_key)?;
                let mut out_header = header.clone();
                let src_key = match encrypter.compute_content_encryption_key(
                    &enc,
                    &header,
                    &mut out_header,
                )? {
                    Some(val) => val,
                    None => Cow::Owned(util::random_bytes(enc.key_len())),
                };
                let encrypted_key = encrypter.encrypt(&src_key, &header, &mut out_header)?;

                out_header.set_algorithm(alg.name());
                let decrypter = alg.decrypter_from_der(&private_key)?;
                let dst_key = decrypter.decrypt(encrypted_key.as_deref(), &enc, &out_header)?;

                assert_eq!(&src_key, &dst_key);
            }
        }

        Ok(())
    }

    #[test]
    fn encrypt_and_decrypt_ecdh_es_with_pem() -> Result<()> {
        let enc = AescbcHmacJweEncryption::A128cbcHs256;

        for alg in vec![
            EcdhEsJweAlgorithm::EcdhEs,
            EcdhEsJweAlgorithm::EcdhEsA128kw,
            EcdhEsJweAlgorithm::EcdhEsA192kw,
            EcdhEsJweAlgorithm::EcdhEsA256kw,
        ] {
            for key in vec![
                EcdhEsKeyType::Ec(EcCurve::P256),
                EcdhEsKeyType::Ec(EcCurve::P384),
                EcdhEsKeyType::Ec(EcCurve::P521),
                EcdhEsKeyType::Ec(EcCurve::Secp256k1),
                EcdhEsKeyType::Ecx(EcxCurve::X25519),
                EcdhEsKeyType::Ecx(EcxCurve::X448),
            ] {
                let private_key = load_file(match key {
                    EcdhEsKeyType::Ec(EcCurve::P256) => "pem/EC_P-256_private.pem",
                    EcdhEsKeyType::Ec(EcCurve::P384) => "pem/EC_P-384_private.pem",
                    EcdhEsKeyType::Ec(EcCurve::P521) => "pem/EC_P-521_private.pem",
                    EcdhEsKeyType::Ec(EcCurve::Secp256k1) => "pem/EC_secp256k1_private.pem",
                    EcdhEsKeyType::Ecx(EcxCurve::X25519) => "pem/X25519_private.pem",
                    EcdhEsKeyType::Ecx(EcxCurve::X448) => "pem/X448_private.pem",
                })?;

                let public_key = load_file(match key {
                    EcdhEsKeyType::Ec(EcCurve::P256) => "pem/EC_P-256_public.pem",
                    EcdhEsKeyType::Ec(EcCurve::P384) => "pem/EC_P-384_public.pem",
                    EcdhEsKeyType::Ec(EcCurve::P521) => "pem/EC_P-521_public.pem",
                    EcdhEsKeyType::Ec(EcCurve::Secp256k1) => "pem/EC_secp256k1_public.pem",
                    EcdhEsKeyType::Ecx(EcxCurve::X25519) => "pem/X25519_public.pem",
                    EcdhEsKeyType::Ecx(EcxCurve::X448) => "pem/X448_public.pem",
                })?;

                let mut header = JweHeader::new();
                header.set_content_encryption(enc.name());

                let encrypter = alg.encrypter_from_pem(&public_key)?;
                let mut out_header = header.clone();
                let src_key = match encrypter.compute_content_encryption_key(
                    &enc,
                    &header,
                    &mut out_header,
                )? {
                    Some(val) => val,
                    None => Cow::Owned(util::random_bytes(enc.key_len())),
                };
                let encrypted_key = encrypter.encrypt(&src_key, &header, &mut out_header)?;

                out_header.set_algorithm(alg.name());
                let decrypter = alg.decrypter_from_pem(&private_key)?;
                let dst_key = decrypter.decrypt(encrypted_key.as_deref(), &enc, &out_header)?;

                assert_eq!(&src_key, &dst_key);
            }
        }

        Ok(())
    }

    #[test]
    fn encrypt_and_decrypt_ecdh_es_with_traditional_pem() -> Result<()> {
        let enc = AesgcmJweEncryption::A128gcm;

        for alg in vec![
            EcdhEsJweAlgorithm::EcdhEs,
            EcdhEsJweAlgorithm::EcdhEsA128kw,
            EcdhEsJweAlgorithm::EcdhEsA192kw,
            EcdhEsJweAlgorithm::EcdhEsA256kw,
        ] {
            for key in vec![
                EcdhEsKeyType::Ec(EcCurve::P256),
                EcdhEsKeyType::Ec(EcCurve::P384),
                EcdhEsKeyType::Ec(EcCurve::P521),
                EcdhEsKeyType::Ec(EcCurve::Secp256k1),
                EcdhEsKeyType::Ecx(EcxCurve::X25519),
                EcdhEsKeyType::Ecx(EcxCurve::X448),
            ] {
                let private_key = load_file(match key {
                    EcdhEsKeyType::Ec(EcCurve::P256) => "pem/EC_P-256_traditional_private.pem",
                    EcdhEsKeyType::Ec(EcCurve::P384) => "pem/EC_P-384_traditional_private.pem",
                    EcdhEsKeyType::Ec(EcCurve::P521) => "pem/EC_P-521_traditional_private.pem",
                    EcdhEsKeyType::Ec(EcCurve::Secp256k1) => {
                        "pem/EC_secp256k1_traditional_private.pem"
                    }
                    EcdhEsKeyType::Ecx(EcxCurve::X25519) => "pem/X25519_traditional_private.pem",
                    EcdhEsKeyType::Ecx(EcxCurve::X448) => "pem/X448_traditional_private.pem",
                })?;
                let public_key = load_file(match key {
                    EcdhEsKeyType::Ec(EcCurve::P256) => "pem/EC_P-256_public.pem",
                    EcdhEsKeyType::Ec(EcCurve::P384) => "pem/EC_P-384_public.pem",
                    EcdhEsKeyType::Ec(EcCurve::P521) => "pem/EC_P-521_public.pem",
                    EcdhEsKeyType::Ec(EcCurve::Secp256k1) => "pem/EC_secp256k1_public.pem",
                    EcdhEsKeyType::Ecx(EcxCurve::X25519) => "pem/X25519_public.pem",
                    EcdhEsKeyType::Ecx(EcxCurve::X448) => "pem/X448_public.pem",
                })?;

                let mut header = JweHeader::new();
                header.set_content_encryption(enc.name());

                let encrypter = alg.encrypter_from_pem(&public_key)?;
                let mut out_header = header.clone();
                let src_key = match encrypter.compute_content_encryption_key(
                    &enc,
                    &header,
                    &mut out_header,
                )? {
                    Some(val) => val,
                    None => Cow::Owned(util::random_bytes(enc.key_len())),
                };
                let encrypted_key = encrypter.encrypt(&src_key, &header, &mut out_header)?;

                out_header.set_algorithm(alg.name());
                let decrypter = alg.decrypter_from_pem(&private_key)?;
                let dst_key = decrypter.decrypt(encrypted_key.as_deref(), &enc, &out_header)?;

                assert_eq!(&src_key, &dst_key);
            }
        }

        Ok(())
    }

    #[test]
    fn encrypt_and_decrypt_ecdh_es_with_jwk() -> Result<()> {
        let enc = AescbcHmacJweEncryption::A128cbcHs256;

        for alg in vec![
            EcdhEsJweAlgorithm::EcdhEs,
            EcdhEsJweAlgorithm::EcdhEsA128kw,
            EcdhEsJweAlgorithm::EcdhEsA192kw,
            EcdhEsJweAlgorithm::EcdhEsA256kw,
        ] {
            for key in vec![
                EcdhEsKeyType::Ec(EcCurve::P256),
                EcdhEsKeyType::Ec(EcCurve::P384),
                EcdhEsKeyType::Ec(EcCurve::P521),
                EcdhEsKeyType::Ec(EcCurve::Secp256k1),
                EcdhEsKeyType::Ecx(EcxCurve::X25519),
                EcdhEsKeyType::Ecx(EcxCurve::X448),
            ] {
                let private_key = load_file(match key {
                    EcdhEsKeyType::Ec(EcCurve::P256) => "jwk/EC_P-256_private.jwk",
                    EcdhEsKeyType::Ec(EcCurve::P384) => "jwk/EC_P-384_private.jwk",
                    EcdhEsKeyType::Ec(EcCurve::P521) => "jwk/EC_P-521_private.jwk",
                    EcdhEsKeyType::Ec(EcCurve::Secp256k1) => "jwk/EC_secp256k1_private.jwk",
                    EcdhEsKeyType::Ecx(EcxCurve::X25519) => "jwk/OKP_X25519_private.jwk",
                    EcdhEsKeyType::Ecx(EcxCurve::X448) => "jwk/OKP_X448_private.jwk",
                })?;

                let public_key = load_file(match key {
                    EcdhEsKeyType::Ec(EcCurve::P256) => "jwk/EC_P-256_public.jwk",
                    EcdhEsKeyType::Ec(EcCurve::P384) => "jwk/EC_P-384_public.jwk",
                    EcdhEsKeyType::Ec(EcCurve::P521) => "jwk/EC_P-521_public.jwk",
                    EcdhEsKeyType::Ec(EcCurve::Secp256k1) => "jwk/EC_secp256k1_public.jwk",
                    EcdhEsKeyType::Ecx(EcxCurve::X25519) => "jwk/OKP_X25519_public.jwk",
                    EcdhEsKeyType::Ecx(EcxCurve::X448) => "jwk/OKP_X448_public.jwk",
                })?;

                let mut header = JweHeader::new();
                header.set_content_encryption(enc.name());

                let public_key = Jwk::from_bytes(&public_key)?;
                let encrypter = alg.encrypter_from_jwk(&public_key)?;
                let mut out_header = header.clone();
                let src_key = match encrypter.compute_content_encryption_key(
                    &enc,
                    &header,
                    &mut out_header,
                )? {
                    Some(val) => val,
                    None => Cow::Owned(util::random_bytes(enc.key_len())),
                };
                let encrypted_key = encrypter.encrypt(&src_key, &header, &mut out_header)?;

                out_header.set_algorithm(alg.name());
                let private_key = Jwk::from_bytes(&private_key)?;
                let decrypter = alg.decrypter_from_jwk(&private_key)?;
                let dst_key = decrypter.decrypt(encrypted_key.as_deref(), &enc, &out_header)?;

                assert_eq!(&src_key, &dst_key);
            }
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

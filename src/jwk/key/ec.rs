use anyhow::bail;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::elliptic_curve::{
    ecdh::diffie_hellman,
    pkcs8::{DecodePrivateKey, DecodePublicKey},
    sec1::ToSec1Point,
    Generate,
};
use rand::rngs::SysRng;

use crate::jwk::alg::ec::{EcCurve, EcKeyPair};

macro_rules! define_ec_keys {
    ($($curve:ident => $backend:ident),+ $(,)?) => {
        #[derive(Debug, Clone)]
        pub(crate) enum EcPrivateKey {
            $($curve($backend::SecretKey),)+
        }

        #[derive(Debug, Clone)]
        pub(crate) enum EcPublicKey {
            $($curve($backend::PublicKey),)+
        }

        impl EcPrivateKey {
            pub(super) fn generate(curve: EcCurve) -> anyhow::Result<Self> {
                match curve {
                    $(EcCurve::$curve => Ok(Self::$curve(
                        $backend::SecretKey::try_generate_from_rng(&mut SysRng)?,
                    )),)+
                }
            }

            pub(super) fn from_der(der: &[u8], curve: EcCurve) -> anyhow::Result<Self> {
                match curve {
                    $(EcCurve::$curve => Ok(Self::$curve(
                        $backend::SecretKey::from_pkcs8_der(der)?,
                    )),)+
                }
            }

            pub(super) fn private_der(&self) -> Vec<u8> {
                match self {
                    $(Self::$curve(key) => key.to_sec1_der().unwrap().to_vec(),)+
                }
            }

            pub(super) fn pkcs8_der(&self) -> Vec<u8> {
                match self {
                    $(Self::$curve(key) => EcKeyPair::to_pkcs8(
                        &key.to_sec1_der().unwrap(),
                        false,
                        EcCurve::$curve,
                    ),)+
                }
            }

            pub(super) fn public_der(&self) -> Vec<u8> {
                match self {
                    $(Self::$curve(key) => EcKeyPair::to_pkcs8(
                        key.public_key().to_sec1_point(false).as_bytes(),
                        true,
                        EcCurve::$curve,
                    ),)+
                }
            }

            pub(super) fn scalar(&self) -> Vec<u8> {
                match self {
                    $(Self::$curve(key) => key.to_bytes().to_vec(),)+
                }
            }

            pub(super) fn coordinates(&self) -> (Vec<u8>, Vec<u8>) {
                match self {
                    $(Self::$curve(key) => {
                        let point = key.public_key().to_sec1_point(false);
                        (point.x().unwrap().to_vec(), point.y().unwrap().to_vec())
                    },)+
                }
            }

            pub(super) fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
                match self {
                    $(Self::$curve(key) => {
                        let signer = $backend::ecdsa::SigningKey::from(key);
                        let signature: $backend::ecdsa::Signature = signer.try_sign(message)?;
                        Ok(signature.to_bytes().to_vec())
                    },)+
                }
            }

            pub(super) fn derive(&self, peer: &EcPublicKey) -> anyhow::Result<Vec<u8>> {
                match (self, peer) {
                    $((Self::$curve(key), EcPublicKey::$curve(peer)) => {
                        let shared = diffie_hellman(key.to_nonzero_scalar(), peer.as_affine());
                        Ok(shared.raw_secret_bytes().to_vec())
                    },)+
                    _ => bail!("Incompatible ECDH curves."),
                }
            }
        }

        impl EcPublicKey {
            pub(super) fn from_der(der: &[u8], curve: EcCurve) -> anyhow::Result<Self> {
                match curve {
                    $(EcCurve::$curve => Ok(Self::$curve(
                        $backend::PublicKey::from_public_key_der(der)?,
                    )),)+
                }
            }
        }
    };
}

define_ec_keys!(P256 => p256, P384 => p384, P521 => p521, Secp256k1 => k256);

impl EcPublicKey {
    pub(super) fn verify(&self, message: &[u8], signature: &[u8]) -> anyhow::Result<()> {
        match self {
            Self::P256(key) => p256::ecdsa::VerifyingKey::from(key)
                .verify(message, &p256::ecdsa::Signature::from_slice(signature)?)?,
            Self::P384(key) => p384::ecdsa::VerifyingKey::from(key)
                .verify(message, &p384::ecdsa::Signature::from_slice(signature)?)?,
            Self::P521(key) => p521::ecdsa::VerifyingKey::from(key)
                .verify(message, &p521::ecdsa::Signature::from_slice(signature)?)?,
            Self::Secp256k1(key) => {
                let signature = k256::ecdsa::Signature::from_slice(signature)?;
                // JOSE accepts either representative of the ECDSA s component.
                let signature = signature.normalize_s();
                k256::ecdsa::VerifyingKey::from(key).verify(message, &signature)?;
            }
        }
        Ok(())
    }
}

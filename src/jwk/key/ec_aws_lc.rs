use std::sync::Arc;

use anyhow::{bail, Context};
use aws_lc_rs::{
    agreement,
    encoding::{AsBigEndian, AsDer, EcPrivateKeyBin, EcPrivateKeyRfc5915Der},
    rand::SystemRandom,
    signature::{self, EcdsaKeyPair, KeyPair, ParsedPublicKey},
};
use pkcs8::{der::Decode, SubjectPublicKeyInfoRef};

use crate::jwk::alg::ec::{EcCurve, EcKeyPair};

#[derive(Debug, Clone)]
pub(crate) struct EcPrivateKey {
    curve: EcCurve,
    key: EcdsaKeyPair,
}

#[derive(Debug, Clone)]
pub(crate) struct EcPublicKey {
    curve: EcCurve,
    key: Arc<ParsedPublicKey>,
}

impl EcPrivateKey {
    pub(super) fn generate(curve: EcCurve) -> anyhow::Result<Self> {
        Ok(Self {
            curve,
            key: EcdsaKeyPair::generate(signing_algorithm(curve))?,
        })
    }

    pub(super) fn from_der(der: &[u8], curve: EcCurve) -> anyhow::Result<Self> {
        Ok(Self {
            curve,
            key: EcdsaKeyPair::from_pkcs8(signing_algorithm(curve), der)?,
        })
    }

    pub(super) fn private_der(&self) -> Vec<u8> {
        let der: EcPrivateKeyRfc5915Der<'_> = self.key.private_key().as_der().unwrap();
        der.as_ref().to_vec()
    }

    pub(super) fn pkcs8_der(&self) -> Vec<u8> {
        self.key.to_pkcs8v1().unwrap().as_ref().to_vec()
    }

    pub(super) fn public_der(&self) -> Vec<u8> {
        EcKeyPair::to_pkcs8(self.key.public_key().as_ref(), true, self.curve)
    }

    pub(super) fn scalar(&self) -> Vec<u8> {
        self.scalar_bytes().unwrap().as_ref().to_vec()
    }

    fn scalar_bytes(&self) -> anyhow::Result<EcPrivateKeyBin<'static>> {
        Ok(self.key.private_key().as_be_bytes()?)
    }

    pub(super) fn coordinates(&self) -> (Vec<u8>, Vec<u8>) {
        let point = &self.key.public_key().as_ref()[1..];
        let (x, y) = point.split_at(point.len() / 2);
        (x.to_vec(), y.to_vec())
    }

    pub(super) fn sign(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(self
            .key
            .sign(&SystemRandom::new(), message)?
            .as_ref()
            .to_vec())
    }

    pub(super) fn derive(&self, peer: &EcPublicKey) -> anyhow::Result<Vec<u8>> {
        if self.curve != peer.curve {
            bail!("Incompatible ECDH curves.");
        }
        let scalar = self.scalar_bytes()?;
        let algorithm = match self.curve {
            EcCurve::P256 => &agreement::ECDH_P256,
            EcCurve::P384 => &agreement::ECDH_P384,
            EcCurve::P521 => &agreement::ECDH_P521,
            // The AWS-LC Rust API has secp256k1 signature support only.
            EcCurve::Secp256k1 => {
                let secret = k256::SecretKey::from_slice(scalar.as_ref())?;
                let public = k256::PublicKey::from_sec1_bytes(peer.key.as_ref().as_ref())?;
                let shared =
                    k256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
                return Ok(shared.raw_secret_bytes().to_vec());
            }
        };
        crate::aws_lc::derive(algorithm, scalar.as_ref(), peer.key.as_ref().as_ref())
    }
}

impl EcPublicKey {
    pub(super) fn from_der(der: &[u8], curve: EcCurve) -> anyhow::Result<Self> {
        if EcKeyPair::detect_pkcs8(der, true) != Some(curve) {
            bail!("Invalid EC public key algorithm identifier.");
        }
        let info = SubjectPublicKeyInfoRef::from_der(der)?;
        let point = info
            .subject_public_key
            .as_bytes()
            .context("Invalid EC public key bit string.")?;
        let algorithm = match curve {
            EcCurve::P256 => &signature::ECDSA_P256_SHA256_FIXED,
            EcCurve::P384 => &signature::ECDSA_P384_SHA384_FIXED,
            EcCurve::P521 => &signature::ECDSA_P521_SHA512_FIXED,
            EcCurve::Secp256k1 => &signature::ECDSA_P256K1_SHA256_FIXED,
        };
        let key = ParsedPublicKey::new(algorithm, point)?;
        Ok(Self {
            curve,
            key: Arc::new(key),
        })
    }

    pub(super) fn verify(&self, message: &[u8], signature: &[u8]) -> anyhow::Result<()> {
        Ok(self.key.verify_sig(message, signature)?)
    }
}

fn signing_algorithm(curve: EcCurve) -> &'static signature::EcdsaSigningAlgorithm {
    match curve {
        EcCurve::P256 => &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        EcCurve::P384 => &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
        EcCurve::P521 => &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
        EcCurve::Secp256k1 => &signature::ECDSA_P256K1_SHA256_FIXED_SIGNING,
    }
}

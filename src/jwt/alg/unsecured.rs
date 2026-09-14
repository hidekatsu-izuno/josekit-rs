use std::ops::Deref;

use anyhow::bail;
#[cfg(feature = "kapun-provider")]
use kapun_crypto_provider::{KeyEncoding, Metadata, Signer, Signing, Verifier, Verifying};

use crate::jws::{JwsAlgorithm, JwsSigner, JwsVerifier};
use crate::JoseError;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum UnsecuredJwsAlgorithm {
    None,
}

impl UnsecuredJwsAlgorithm {
    pub fn signer(&self) -> UnsecuredJwsSigner {
        UnsecuredJwsSigner {
            algorithm: self.clone(),
        }
    }

    pub fn verifier(&self) -> UnsecuredJwsVerifier {
        UnsecuredJwsVerifier {
            algorithm: self.clone(),
        }
    }
}

impl JwsAlgorithm for UnsecuredJwsAlgorithm {
    fn name(&self) -> &str {
        "none"
    }

    fn box_clone(&self) -> Box<dyn JwsAlgorithm> {
        Box::new(self.clone())
    }
}

impl Deref for UnsecuredJwsAlgorithm {
    type Target = dyn JwsAlgorithm;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct UnsecuredJwsSigner {
    algorithm: UnsecuredJwsAlgorithm,
}
#[cfg(feature = "kapun-provider")]
impl KeyEncoding for UnsecuredJwsSigner {}
#[cfg(feature = "kapun-provider")]
impl Metadata for UnsecuredJwsSigner {}
#[cfg(feature = "kapun-provider")]
impl Signing for UnsecuredJwsSigner {
    fn kapun_sign(&self, _data: Vec<u8>) -> Result<Vec<u8>, kapun_crypto_provider::SigningProblem> {
        todo!()
    }

    fn kapun_sign_hash(
        &self,
        _hash: Vec<u8>,
    ) -> Result<Vec<u8>, kapun_crypto_provider::SigningProblem> {
        todo!()
    }
}
#[cfg(feature = "kapun-provider")]
impl Signer for UnsecuredJwsSigner {}

impl JwsSigner for UnsecuredJwsSigner {
    fn algorithm(&self) -> &dyn JwsAlgorithm {
        &self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        None
    }

    fn signature_len(&self) -> usize {
        0
    }

    fn sign(&self, _message: &[u8]) -> Result<Vec<u8>, JoseError> {
        Ok(vec![])
    }

    fn box_clone(&self) -> Box<dyn JwsSigner> {
        Box::new(self.clone())
    }
}

impl Deref for UnsecuredJwsSigner {
    type Target = dyn JwsSigner;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct UnsecuredJwsVerifier {
    algorithm: UnsecuredJwsAlgorithm,
}
#[cfg(feature = "kapun-provider")]
impl KeyEncoding for UnsecuredJwsVerifier {}
#[cfg(feature = "kapun-provider")]
impl Metadata for UnsecuredJwsVerifier {}
#[cfg(feature = "kapun-provider")]
impl Verifying for UnsecuredJwsVerifier {
    fn kapun_verify(
        &self,
        _data: Vec<u8>,
        _signature: Vec<u8>,
    ) -> Result<(), kapun_crypto_provider::VerificationProblem> {
        todo!()
    }

    fn kapun_verify_hash(
        &self,
        _hash: Vec<u8>,
        _signature: Vec<u8>,
    ) -> Result<(), kapun_crypto_provider::VerificationProblem> {
        todo!()
    }
}
#[cfg(feature = "kapun-provider")]
impl Verifier for UnsecuredJwsVerifier {}

impl JwsVerifier for UnsecuredJwsVerifier {
    fn algorithm(&self) -> &dyn JwsAlgorithm {
        &self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        None
    }

    fn verify(&self, _message: &[u8], signature: &[u8]) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            if signature.len() != 0 {
                bail!(
                    "The length of none algorithm signature must be 0: {}",
                    signature.len()
                );
            }

            Ok(())
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }

    fn box_clone(&self) -> Box<dyn JwsVerifier> {
        Box::new(self.clone())
    }
}

impl Deref for UnsecuredJwsVerifier {
    type Target = dyn JwsVerifier;

    fn deref(&self) -> &Self::Target {
        self
    }
}

use std::{any::Any, fmt::Debug};

#[cfg(feature = "kapun-provider")]
pub use kapun_crypto_provider::{Signer as JwsProviderSigner, Verifier as JwsProviderVerifier};

use crate::JoseError;

#[cfg(not(feature = "kapun-provider"))]
pub trait JwsProviderSigner {}

#[cfg(not(feature = "kapun-provider"))]
impl<T> JwsProviderSigner for T {}

#[cfg(not(feature = "kapun-provider"))]
pub trait JwsProviderVerifier {}

#[cfg(not(feature = "kapun-provider"))]
impl<T> JwsProviderVerifier for T {}

pub trait JwsAlgorithm: Debug + Send + Sync {
    /// Return the "alg" (algorithm) header parameter value of JWS.
    fn name(&self) -> &str;

    fn box_clone(&self) -> Box<dyn JwsAlgorithm>;
}

impl PartialEq for Box<dyn JwsAlgorithm> {
    fn eq(&self, other: &Self) -> bool {
        self == other
    }
}

impl Eq for Box<dyn JwsAlgorithm> {}

impl Clone for Box<dyn JwsAlgorithm> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

pub trait JwsSigner: JwsProviderSigner + Debug + Send + Sync + Any {
    /// Return the source algorithm instance.
    fn algorithm(&self) -> &dyn JwsAlgorithm;

    /// Return the source key ID.
    /// The default value is a value of kid parameter in JWK.
    fn key_id(&self) -> Option<&str>;

    /// Return the signature length of JWS.
    fn signature_len(&self) -> usize;

    /// Return a signature of the data.
    ///
    /// # Arguments
    ///
    /// * `message` - The message data to sign.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError>;

    /// Return a signature directly on the digest.
    ///
    /// # Arguments
    ///
    /// * `message` - The message data to sign.
    fn sign_prehashed(&self, _digest: &[u8]) -> Result<Vec<u8>, JoseError> {
        Err(JoseError::UnsupportedSignatureAlgorithm(anyhow::anyhow!(
            "Signed Prehashed not implemented"
        )))
    }

    fn box_clone(&self) -> Box<dyn JwsSigner>;
}

impl Clone for Box<dyn JwsSigner> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

pub trait JwsVerifier: JwsProviderVerifier + Debug + Send + Sync {
    /// Return the source algrithm instance.
    fn algorithm(&self) -> &dyn JwsAlgorithm;

    /// Return the source key ID.
    /// The default value is a value of kid parameter in JWK.
    fn key_id(&self) -> Option<&str>;

    /// Verify the data by the signature.
    ///
    /// # Arguments
    ///
    /// * `message` - a message data to verify.
    /// * `signature` - a signature data.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError>;

    /// Verify the data by the signature using the prehashed version.
    /// For EcDSA or RSA this is equivalent as the normal verification,
    /// but for algorithms using some kind of Fiat-Shamir Transform, they
    /// usually contain a context variable specifying if it was the prehashed variant
    ///
    /// # Arguments
    ///
    /// * `message` - a message data to verify.
    /// * `signature` - a signature data.
    fn verify_prehashed(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError> {
        self.verify(message, signature)
    }

    fn box_clone(&self) -> Box<dyn JwsVerifier>;
}

impl Clone for Box<dyn JwsVerifier> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

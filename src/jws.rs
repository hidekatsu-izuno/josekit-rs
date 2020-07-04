pub mod ecdsa;
pub mod eddsa;
pub mod hmac;
pub mod rsa;
pub mod rsapss;

use std::io::Read;

use crate::jwk::Jwk;
use crate::error::JoseError;

pub use crate::jws::ecdsa::EcdsaJwsAlgorithm::ES256;
pub use crate::jws::ecdsa::EcdsaJwsAlgorithm::ES256K;
pub use crate::jws::ecdsa::EcdsaJwsAlgorithm::ES384;
pub use crate::jws::ecdsa::EcdsaJwsAlgorithm::ES512;
pub use crate::jws::eddsa::EddsaJwsAlgorithm::EDDSA;
pub use crate::jws::hmac::HmacJwsAlgorithm::HS256;
pub use crate::jws::hmac::HmacJwsAlgorithm::HS384;
pub use crate::jws::hmac::HmacJwsAlgorithm::HS512;
pub use crate::jws::rsa::RsaJwsAlgorithm::RS256;
pub use crate::jws::rsa::RsaJwsAlgorithm::RS384;
pub use crate::jws::rsa::RsaJwsAlgorithm::RS512;
pub use crate::jws::rsapss::RsaPssJwsAlgorithm::PS256;
pub use crate::jws::rsapss::RsaPssJwsAlgorithm::PS384;
pub use crate::jws::rsapss::RsaPssJwsAlgorithm::PS512;

pub trait JwsAlgorithm {
    /// Return the "alg" (algorithm) header parameter value of JWS.
    fn name(&self) -> &str;

    /// Return the "kty" (key type) header parameter value of JWS.
    fn key_type(&self) -> &str;

    /// Return a signer from a JWK private key.
    ///
    /// # Arguments
    /// * `jwk` - A JWK private key.
    fn signer_from_jwk(&self, jwk: &Jwk) -> Result<Box<dyn JwsSigner>, JoseError>;

    /// Return a verifier from a JWK key.
    ///
    /// # Arguments
    /// * `jwk` - A JWK key.
    fn verifier_from_jwk(&self, jwk: &Jwk) -> Result<Box<dyn JwsVerifier>, JoseError>;
}

pub trait JwsSigner {
    /// Return the source algrithm instance.
    fn algorithm(&self) -> &dyn JwsAlgorithm;

    /// Return kid value.
    fn key_id(&self) -> Option<&str>;

    /// Set a compared value for a kid header claim (kid).
    ///
    /// # Arguments
    /// * `key_id` - A key id
    fn set_key_id(&mut self, key_id: &str);

    /// Remove a compared value for a kid header claim (kid).
    fn remove_key_id(&mut self);

    /// Return a signature of the data.
    ///
    /// # Arguments
    /// * `message` - The message data to sign.
    fn sign(&self, message: &mut dyn Read) -> Result<Vec<u8>, JoseError>;
}

pub trait JwsVerifier {
    /// Return the source algrithm instance.
    fn algorithm(&self) -> &dyn JwsAlgorithm;

    /// Return kid value.
    fn key_id(&self) -> Option<&str>;

    /// Set a compared value for a kid header claim (kid).
    ///
    /// # Arguments
    /// * `key_id` - A key id
    fn set_key_id(&mut self, key_id: &str);

    /// Unset a compared value for a kid header claim (kid).
    fn unset_key_id(&mut self);

    /// Verify the data by the signature.
    ///
    /// # Arguments
    /// * `message` - The message data to verify.
    /// * `signature` - The signature data.
    fn verify(&self, message: &mut dyn Read, signature: &[u8]) -> Result<(), JoseError>;
}

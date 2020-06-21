pub mod ecdsa;
pub mod eddsa;
pub mod hmac;
pub mod rsa;
pub mod rsapss;
mod util;

use crate::error::JoseError;

pub use crate::jws::ecdsa::EcdsaJwsAlgorithm::ES256;
pub use crate::jws::ecdsa::EcdsaJwsAlgorithm::ES384;
pub use crate::jws::ecdsa::EcdsaJwsAlgorithm::ES512;
pub use crate::jws::ecdsa::EcdsaJwsAlgorithm::ES256K;
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
    /// Return the "alg" (JwsAlgorithm) header parameter value of JWE.
    fn name(&self) -> &str;
}

pub trait JwsSigner<T: JwsAlgorithm> {
    /// Return the source algrithm instance.
    fn algorithm(&self) -> &T;

    /// Return a signature of the data.
    ///
    /// # Arguments
    /// * `message` - The message data to sign.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError>;
}

pub trait JwsVerifier<T: JwsAlgorithm> {
    /// Return the source algrithm instance.
    fn algorithm(&self) -> &T;

    /// Verify the data by the signature.
    ///
    /// # Arguments
    /// * `message` - The message data to verify.
    /// * `signature` - The signature data.
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError>;
}

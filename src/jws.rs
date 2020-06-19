pub mod ecdsa;
pub mod eddsa;
pub mod hmac;
pub mod rsa;
pub mod rsapss;
mod util;

use crate::error::JoseError;

pub use crate::jws::ecdsa::ES256;
pub use crate::jws::ecdsa::ES384;
pub use crate::jws::ecdsa::ES512;
pub use crate::jws::eddsa::EDDSA;
pub use crate::jws::hmac::HS256;
pub use crate::jws::hmac::HS384;
pub use crate::jws::hmac::HS512;
pub use crate::jws::rsa::RS256;
pub use crate::jws::rsa::RS384;
pub use crate::jws::rsa::RS512;
pub use crate::jws::rsapss::PS256;
pub use crate::jws::rsapss::PS384;
pub use crate::jws::rsapss::PS512;

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

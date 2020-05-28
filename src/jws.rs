pub mod ecdsa;
pub mod hmac;
pub mod rsa;
mod der;
mod util;

use crate::error::JwtError;

pub use crate::jws::hmac::HS256;
pub use crate::jws::hmac::HS384;
pub use crate::jws::hmac::HS512;
pub use crate::jws::rsa::RS256;
pub use crate::jws::rsa::RS384;
pub use crate::jws::rsa::RS512;
pub use crate::jws::rsa::PS256;
pub use crate::jws::rsa::PS384;
pub use crate::jws::rsa::PS512;
pub use crate::jws::ecdsa::ES256;
pub use crate::jws::ecdsa::ES384;
pub use crate::jws::ecdsa::ES512;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum HashAlgorithm {
    /// SHA-256
    SHA256,

    /// SHA-384
    SHA384,

    /// SHA-512
    SHA512,
}

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
    /// * `data` - The data to sign.
    fn sign(&self, data: &[&[u8]]) -> Result<Vec<u8>, JwtError>;
}

pub trait JwsVerifier<T: JwsAlgorithm> {
    /// Return the source algrithm instance.
    fn algorithm(&self) -> &T;

    /// Verify the data by the signature.
    ///
    /// # Arguments
    /// * `data` - The data to verify.
    /// * `signature` - The signature data.
    fn verify(&self, data: &[&[u8]], signature: &[u8]) -> Result<(), JwtError>;
}

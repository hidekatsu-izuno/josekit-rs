pub mod ecdsa;
pub mod hmac;
pub mod rsa;
mod openssl;

use crate::error::JwtError;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum HashAlgorithm {
    /// SHA-256
    SHA256,

    /// SHA-384
    SHA384,

    /// SHA-512
    SHA512,
}

pub trait Algorithm {
    /// Return the "alg" (Algorithm) header parameter value of JWE.
    fn name(&self) -> &str;
}

pub trait Signer<T: Algorithm> {
    /// Return the source algrithm instance.
    fn algorithm(&self) -> &T;

    /// Return a signature of the data.
    ///
    /// # Arguments
    /// * `data` - The data to sign.
    fn sign(&self, data: &[&[u8]]) -> Result<Vec<u8>, JwtError>;
}

pub trait Verifier<T: Algorithm> {
    /// Return the source algrithm instance.
    fn algorithm(&self) -> &T;

    /// Verify the data by the signature.
    ///
    /// # Arguments
    /// * `data` - The data to verify.
    /// * `signature` - The signature data.
    fn verify(&self, data: &[&[u8]], signature: &[u8]) -> Result<(), JwtError>;
}

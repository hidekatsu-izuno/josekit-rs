pub mod hmac;
pub mod rsa;
pub mod ecdsa;

use crate::error::JwtError;

#[derive(Debug, Copy, Clone)]
pub enum HashAlgorithm {
    SHA256,
    SHA384,
    SHA512
}

pub trait Algorithm {
    fn name(&self) -> &str;
}

pub trait Signer<T: Algorithm> {
    fn algorithm(&self) -> &T;

    fn sign(&self, data: &[&[u8]]) -> Result<Vec<u8>, JwtError>;
}

pub trait Verifier<T: Algorithm> {
    fn algorithm(&self) -> &T;

    fn verify(&self, data: &[&[u8]], signature: &[u8]) -> Result<(), JwtError>;
}

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

pub trait Signer {
    fn sign(&self, target: &[u8]) -> Result<Vec<u8>, JwtError>;
}

pub trait Verifier {
    fn verify(&self, target: &[u8], signature: &[u8]) -> Result<(), JwtError>;
}

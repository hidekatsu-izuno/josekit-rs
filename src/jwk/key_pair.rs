pub mod ec;
pub mod ecx;
pub mod ed;
pub mod rsa;
pub mod rsapss;

use std::fmt::Debug;

use crate::jwk::Jwk;

pub trait KeyPair: Debug + Send + Sync {
    fn algorithm(&self) -> Option<&str>;

    fn to_der_private_key(&self) -> Vec<u8>;
    fn to_der_public_key(&self) -> Vec<u8>;
    fn to_pem_private_key(&self) -> Vec<u8>;
    fn to_pem_public_key(&self) -> Vec<u8>;
    fn to_jwk_private_key(&self) -> Jwk;
    fn to_jwk_public_key(&self) -> Jwk;
    fn to_jwk_keypair(&self) -> Jwk;

    fn box_clone(&self) -> Box<dyn KeyPair>;
}

impl PartialEq for Box<dyn KeyPair> {
    fn eq(&self, other: &Self) -> bool {
        self == other
    }
}

impl Eq for Box<dyn KeyPair> {}

impl Clone for Box<dyn KeyPair> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

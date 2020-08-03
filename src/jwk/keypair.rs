use crate::jwk::Jwk;

pub trait KeyPair {
    fn to_der_private_key(&self) -> Vec<u8>;
    fn to_der_public_key(&self) -> Vec<u8>;
    fn to_pem_private_key(&self) -> Vec<u8>;
    fn to_pem_public_key(&self) -> Vec<u8>;
    fn to_jwk_private_key(&self) -> Jwk;
    fn to_jwk_public_key(&self) -> Jwk;
    fn to_jwk_keypair(&self) -> Jwk;
}

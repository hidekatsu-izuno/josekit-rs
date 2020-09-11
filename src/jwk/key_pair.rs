pub mod ec;
pub mod ecx;
pub mod ed;
pub mod rsa;
pub mod rsapss;

pub use crate::jwk::key_pair::ec::EcCurve;
pub use crate::jwk::key_pair::ec::EcKeyPair;
pub use crate::jwk::key_pair::ecx::EcxCurve;
pub use crate::jwk::key_pair::ecx::EcxKeyPair;
pub use crate::jwk::key_pair::ed::EdCurve;
pub use crate::jwk::key_pair::ed::EdKeyPair;
pub use crate::jwk::key_pair::rsa::RsaKeyPair;
pub use crate::jwk::key_pair::rsapss::RsaPssKeyPair;

use std::fmt::Debug;

use crate::jwk::Jwk;

pub trait KeyPair: Debug + Send + Sync {
    /// Return the applicatable algorithm.
    fn algorithm(&self) -> Option<&str>;

    /// Return the applicatable key ID.
    fn key_id(&self) -> Option<&str>;

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

use crate::jwk::Jwk;
use crate::error::JoseError;

pub trait JweEncryption {
    /// Return the "enc" (encryption) header parameter value of JWE.
    fn name(&self) -> &str;

    /// Return the signer from a JWK private key.
    ///
    /// # Arguments
    /// * `jwk` - a JWK private key.
    fn encrypter_from_jwk(&self, jwk: &Jwk) -> Result<Box<dyn JweEncrypter>, JoseError>;

    /// Return the verifier from a JWK key.
    ///
    /// # Arguments
    /// * `jwk` - a JWK key.
    fn verifier_from_jwk(&self, jwk: &Jwk) -> Result<Box<dyn JweDecrypter>, JoseError>;
}

pub trait JweEncrypter {

}

pub trait JweDecrypter {
    
}
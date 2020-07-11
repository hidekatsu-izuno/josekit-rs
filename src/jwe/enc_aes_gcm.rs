use crate::jwe::{JweAlgorithm, JweEncryption, JweEncrypter, JweDecrypter};
use crate::jwk::Jwk;
use crate::error::JoseError;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AesGcmJweEncryption {
    /// AES GCM using 128-bit key
    A128GCM,
    /// AES GCM using 192-bit key
    A192GCM,
    /// AES GCM using 256-bit key
    A256GCM,
}

use crate::jwe::JweContentEncryption;
use crate::jose::JoseError;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AesCbcHmacJweEncryption {
    /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm
    A128CbcHS256,
    /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm
    A192CbcHS384,
    /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm
    A256CbcHS512,
}

impl JweContentEncryption for AesCbcHmacJweEncryption {
    fn name(&self) -> &str {
        match self {
            Self::A128CbcHS256 => "A128CBC-HS256",
            Self::A192CbcHS384 => "A192CBC-HS384",
            Self::A256CbcHS512 => "A256CBC-HS512",
        }
    }

    fn iv_len(&self) -> usize {
        16
    }

    fn encrypt(&self, message: &[u8], iv: &[u8], secret: &[u8]) -> Result<Vec<u8>, JoseError> {
        todo!()
    }

    fn decrypt(&self, data: &[u8], iv: &[u8], secret: &[u8]) -> Result<Vec<u8>, JoseError> {
        todo!()
    }

    fn digest(&self, message: &[u8]) -> Result<Vec<u8>, JoseError> {
        todo!()
    }

    fn box_clone(&self) -> Box<dyn JweContentEncryption> {
        Box::new(self.clone())
    }
}

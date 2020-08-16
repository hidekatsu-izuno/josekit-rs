use crate::jwe::JweContentEncryption;
use crate::jose::JoseError;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AesGcmJweEncryption {
    /// AES GCM using 128-bit key
    A128Gcm,
    /// AES GCM using 192-bit key
    A192Gcm,
    /// AES GCM using 256-bit key
    A256Gcm,
}

impl JweContentEncryption for AesGcmJweEncryption {
    fn name(&self) -> &str {
        match self {
            Self::A128Gcm => "A128GCM",
            Self::A192Gcm => "A192GCM",
            Self::A256Gcm => "A256GCM",
        }
    }

    fn enc_key_len(&self) -> usize {
        16
    }

    fn mac_key_len(&self) -> usize {
        0
    }

    fn iv_len(&self) -> usize {
        12
    }

    fn encrypt(&self, message: &[u8], iv: &[u8], secret: &[u8]) -> Result<Vec<u8>, JoseError> {
        todo!()
    }

    fn decrypt(&self, data: &[u8], iv: &[u8], secret: &[u8]) -> Result<Vec<u8>, JoseError> {
        todo!()
    }
    
    fn sign(&self, _message: &[u8], _mac_key: &[u8]) -> Result<Vec<u8>, JoseError> {
        unimplemented!("AES GCM doesn't need to sign.");
    }

    fn box_clone(&self) -> Box<dyn JweContentEncryption> {
        Box::new(self.clone())
    }
}

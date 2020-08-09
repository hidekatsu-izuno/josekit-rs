#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AesGcmJweEncryption {
    /// AES GCM using 128-bit key
    A128Gcm,
    /// AES GCM using 192-bit key
    A192Gcm,
    /// AES GCM using 256-bit key
    A256Gcm,
}

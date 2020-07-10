#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AesGcmJweAlgorithm {
    /// Key wrapping with AES GCM using 128-bit key
    A128GCMKW,
    /// Key wrapping with AES GCM using 192-bit key
    A192GCMKW,
    /// Key wrapping with AES GCM using 256-bit key
    A256GCMKW,
}

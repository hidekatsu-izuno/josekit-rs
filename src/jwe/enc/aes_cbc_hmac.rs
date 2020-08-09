#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AesCbcHmacJweEncryption {
    /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm
    A128CbcHS256,
    /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm
    A192CbcHS384,
    /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm
    A256CbcHS512,
}

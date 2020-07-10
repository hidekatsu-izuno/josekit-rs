#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AesCbcHmacJweEncryption {
    /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm
    A128CBC_HS256,
    /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm
    A192CBC_HS384,
    /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm
    A256CBC_HS512,
}

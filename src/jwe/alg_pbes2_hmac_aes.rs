#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum Pbes2HmacAesJweAlgorithm {
    /// PBES2 with HMAC SHA-256 and "A128KW" wrapping
    PBES2_HS256_A128KW,
    /// PBES2 with HMAC SHA-384 and "A192KW" wrapping
    PBES2_HS384_A192KW,
    /// PBES2 with HMAC SHA-512 and "A256KW" wrapping
    PBES2_HS512_A256KW,
}

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AesJweAlgorithm {
    /// AES Key Wrap with default initial value using 128-bit key
    A128KW,
    /// AES Key Wrap with default initial value using 192-bit key
    A192KW,
    /// AES Key Wrap with default initial value using 256-bit key
    A256KW,
}

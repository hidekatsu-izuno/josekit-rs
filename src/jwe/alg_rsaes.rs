#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum RsaJweAlgorithm {
    /// RSAES-PKCS1-v1_5
    RSA1_5,
    /// RSAES OAEP using default parameters
    RSA_OAEP,
    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
    RSA_OAEP_256,
}

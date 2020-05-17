use thiserror::Error;

#[derive(Error, Debug)]
pub enum JwtError {
    #[error("Unsupported signature algorithm: {0}")]
    UnsupportedSignatureAlgorithm(String),
    
    #[error("Invalid json format: {0}")]
    InvalidJsonFormat(anyhow::Error),

    #[error("Invalid jwt format.")]
    InvalidJwtFormat,

    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(anyhow::Error),

    #[error("Invalid signature: {0}")]
    InvalidSignature(anyhow::Error),
}

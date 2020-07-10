#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum EcdhEsAesJweAlgorithm {
    /// ECDH-ES using Concat KDF and CEK wrapped with "A128KW" 
    ECDH_ES_A128KW,
    /// ECDH-ES using Concat KDF and CEK wrapped with "A192KW" 
    ECDH_ES_A192KW,
    /// ECDH-ES using Concat KDF and CEK wrapped with "A256KW" 
    ECDH_ES_A256KW,
}

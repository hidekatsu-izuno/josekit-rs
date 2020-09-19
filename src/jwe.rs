//! JSON Web Encryption (JWE) support.

pub mod alg;
pub mod enc;
mod jwe_algorithm;
mod jwe_compression;
mod jwe_content_encryption;
mod jwe_context;
mod jwe_header;
pub mod zip;

use once_cell::sync::Lazy;

use crate::JoseError;

pub use crate::jwe::jwe_algorithm::JweAlgorithm;
pub use crate::jwe::jwe_algorithm::JweDecrypter;
pub use crate::jwe::jwe_algorithm::JweEncrypter;
pub use crate::jwe::jwe_compression::JweCompression;
pub use crate::jwe::jwe_content_encryption::JweContentEncryption;
pub use crate::jwe::jwe_context::JweContext;
pub use crate::jwe::jwe_header::JweHeader;

pub use crate::jwe::alg::direct::DirectJweAlgorithm::Dir;

pub use crate::jwe::alg::ecdh_es::EcdhEsJweAlgorithm::EcdhEs;
pub use crate::jwe::alg::ecdh_es::EcdhEsJweAlgorithm::EcdhEsA128Kw;
pub use crate::jwe::alg::ecdh_es::EcdhEsJweAlgorithm::EcdhEsA192Kw;
pub use crate::jwe::alg::ecdh_es::EcdhEsJweAlgorithm::EcdhEsA256Kw;
pub use EcdhEs as ECDH_ES;
pub use EcdhEsA128Kw as ECDH_ES_A128KW;
pub use EcdhEsA192Kw as ECDH_ES_A192KW;
pub use EcdhEsA256Kw as ECDH_ES_A256KW;

pub use crate::jwe::alg::aeskw::AeskwJweAlgorithm::A128Kw;
pub use crate::jwe::alg::aeskw::AeskwJweAlgorithm::A192Kw;
pub use crate::jwe::alg::aeskw::AeskwJweAlgorithm::A256Kw;
pub use A128Kw as A128KW;
pub use A192Kw as A192KW;
pub use A256Kw as A256KW;

pub use crate::jwe::alg::aesgcmkw::AesgcmkwJweAlgorithm::A128GcmKw;
pub use crate::jwe::alg::aesgcmkw::AesgcmkwJweAlgorithm::A192GcmKw;
pub use crate::jwe::alg::aesgcmkw::AesgcmkwJweAlgorithm::A256GcmKw;
pub use A128GcmKw as A128GCMKW;
pub use A192GcmKw as A192GCMKW;
pub use A256GcmKw as A256GCMKW;

pub use crate::jwe::alg::pbes2_hmac_aeskw::Pbes2HmacAeskwJweAlgorithm::Pbes2HS256A128Kw;
pub use crate::jwe::alg::pbes2_hmac_aeskw::Pbes2HmacAeskwJweAlgorithm::Pbes2HS384A192Kw;
pub use crate::jwe::alg::pbes2_hmac_aeskw::Pbes2HmacAeskwJweAlgorithm::Pbes2HS512A256Kw;
pub use Pbes2HS256A128Kw as PBES2_HS256_A128KW;
pub use Pbes2HS384A192Kw as PBES2_HS384_A192KW;
pub use Pbes2HS512A256Kw as PBES2_HS512_A256KW;

#[allow(deprecated)]
pub use crate::jwe::alg::rsaes::RsaesJweAlgorithm::Rsa1_5;
pub use crate::jwe::alg::rsaes::RsaesJweAlgorithm::RsaOaep;
pub use crate::jwe::alg::rsaes::RsaesJweAlgorithm::RsaOaep256;
pub use crate::jwe::alg::rsaes::RsaesJweAlgorithm::RsaOaep384;
pub use crate::jwe::alg::rsaes::RsaesJweAlgorithm::RsaOaep512;
#[allow(deprecated)]
pub use Rsa1_5 as RSA1_5;
pub use RsaOaep as RSA_OAEP;
pub use RsaOaep256 as RSA_OAEP_256;
pub use RsaOaep384 as RSA_OAEP_384;
pub use RsaOaep512 as RSA_OAEP_512;

static DEFAULT_CONTEXT: Lazy<JweContext> = Lazy::new(|| JweContext::new());

/// Return a representation of the data that is formatted by compact serialization.
///
/// # Arguments
///
/// * `payload` - The payload data.
/// * `header` - The JWS heaser claims.
/// * `encrypter` - The JWS encrypter.
pub fn serialize_compact(
    payload: &[u8],
    header: &JweHeader,
    encrypter: &dyn JweEncrypter,
) -> Result<String, JoseError> {
    DEFAULT_CONTEXT.serialize_compact(payload, header, encrypter)
}

/// Return a representation of the data that is formatted by compact serialization.
///
/// # Arguments
///
/// * `payload` - The payload data.
/// * `header` - The JWS heaser claims.
/// * `selector` - a function for selecting the signing algorithm.
pub fn serialize_compact_with_selector<'a, F>(
    payload: &[u8],
    header: &JweHeader,
    selector: F,
) -> Result<String, JoseError>
where
    F: Fn(&JweHeader) -> Option<&'a dyn JweEncrypter>,
{
    DEFAULT_CONTEXT.serialize_compact_with_selector(payload, header, selector)
}

/// Return a representation of the data that is formatted by flattened json serialization.
///
/// # Arguments
///
/// * `protected` - The JWE protected header claims.
/// * `header` - The JWE unprotected header claims.
/// * `aad` - The JWE additional authenticated data.
/// * `payload` - The payload data.
/// * `encrypter` - The JWS encrypter.
pub fn serialize_flattened_json(
    payload: &[u8],
    protected: Option<&JweHeader>,
    unprotected: Option<&JweHeader>,
    header: Option<&JweHeader>,
    aad: Option<&[u8]>,
    encrypter: &dyn JweEncrypter,
) -> Result<String, JoseError> {
    DEFAULT_CONTEXT.serialize_flattened_json(
        payload,
        protected,
        unprotected,
        header,
        aad,
        encrypter,
    )
}

/// Return a representation of the data that is formatted by flatted json serialization.
///
/// # Arguments
///
/// * `payload` - The payload data.
/// * `protected` - The JWS protected header claims.
/// * `header` - The JWS unprotected header claims.
/// * `aad` - The JWE additional authenticated data.
/// * `selector` - a function for selecting the encrypting algorithm.
pub fn serialize_flattened_json_with_selector<'a, F>(
    payload: &[u8],
    protected: Option<&JweHeader>,
    unprotected: Option<&JweHeader>,
    header: Option<&JweHeader>,
    aad: Option<&[u8]>,
    selector: F,
) -> Result<String, JoseError>
where
    F: Fn(&JweHeader) -> Option<&'a dyn JweEncrypter>,
{
    DEFAULT_CONTEXT.serialize_flattened_json_with_selector(
        payload,
        protected,
        unprotected,
        header,
        aad,
        selector,
    )
}

/// Deserialize the input that is formatted by compact serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `decrypter` - The JWS decrypter.
pub fn deserialize_compact(
    input: &str,
    decrypter: &dyn JweDecrypter,
) -> Result<(Vec<u8>, JweHeader), JoseError> {
    DEFAULT_CONTEXT.deserialize_compact(input, decrypter)
}

/// Deserialize the input that is formatted by compact serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `selector` - a function for selecting the decrypting algorithm.
pub fn deserialize_compact_with_selector<'a, F>(
    input: &str,
    selector: F,
) -> Result<(Vec<u8>, JweHeader), JoseError>
where
    F: Fn(&JweHeader) -> Result<Option<&'a dyn JweDecrypter>, JoseError>,
{
    DEFAULT_CONTEXT.deserialize_compact_with_selector(input, selector)
}

/// Deserialize the input that is formatted by flattened json serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `header` - The decoded JWS header claims.
/// * `decrypter` - The JWE decrypter.
pub fn deserialize_json<'a>(
    input: &str,
    decrypter: &'a dyn JweDecrypter,
) -> Result<(Vec<u8>, JweHeader), JoseError> {
    DEFAULT_CONTEXT.deserialize_json(input, decrypter)
}

/// Deserialize the input that is formatted by flattened json serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `selector` - a function for selecting the decrypting algorithm.
pub fn deserialize_json_with_selector<'a, F>(
    input: &str,
    selector: F,
) -> Result<(Vec<u8>, JweHeader), JoseError>
where
    F: Fn(&JweHeader) -> Result<Option<&'a dyn JweDecrypter>, JoseError>,
{
    DEFAULT_CONTEXT.deserialize_json_with_selector(input, selector)
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use serde_json::Value;

    use crate::jwe::{self, Dir, JweAlgorithm, JweHeader};
    use crate::util;
    use crate::JoseHeader;

    #[test]
    fn test_jwe_compact_serialization() -> Result<()> {
        for enc in vec![
            "A128CBC-HS256",
            "A192CBC-HS384",
            "A256CBC-HS512",
            "A128GCM",
            "A256GCM",
            "A256GCM",
        ] {
            let mut src_header = JweHeader::new();
            src_header.set_content_encryption(enc);
            src_header.set_token_type("JWT");
            let src_payload = b"test payload!";

            //println!("{}", enc);

            let alg = Dir;
            let key = match enc {
                "A128CBC-HS256" => util::rand_bytes(32),
                "A192CBC-HS384" => util::rand_bytes(40),
                "A256CBC-HS512" => util::rand_bytes(48),
                "A128GCM" => util::rand_bytes(16),
                "A192GCM" => util::rand_bytes(24),
                "A256GCM" => util::rand_bytes(32),
                _ => unreachable!(),
            };
            let encrypter = alg.encrypter_from_bytes(&key)?;
            let jwe = jwe::serialize_compact(src_payload, &src_header, &encrypter)?;

            let decrypter = alg.decrypter_from_bytes(&key)?;
            let (dst_payload, dst_header) = jwe::deserialize_compact(&jwe, &decrypter)?;

            src_header.set_claim("alg", Some(Value::String(alg.name().to_string())))?;
            assert_eq!(src_header, dst_header);
            assert_eq!(src_payload.to_vec(), dst_payload);
        }

        Ok(())
    }
}

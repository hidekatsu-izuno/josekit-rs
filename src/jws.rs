//! JSON Web Signature (JWS) support.

pub mod alg;
mod jws_algorithm;
mod jws_context;
mod jws_header;
mod jws_multi_signer;

use once_cell::sync::Lazy;

use crate::jose::JoseError;

pub use crate::jws::jws_algorithm::JwsAlgorithm;
pub use crate::jws::jws_algorithm::JwsSigner;
pub use crate::jws::jws_algorithm::JwsVerifier;
pub use crate::jws::jws_context::JwsContext;
pub use crate::jws::jws_header::JwsHeader;
pub use crate::jws::jws_multi_signer::JwsMultiSigner;

#[deprecated(since = "0.4.0", note = "Please use ::jws::alg::HS256")]
pub use crate::jws::alg::hmac::HmacJwsAlgorithm::HS256;
#[deprecated(since = "0.4.0", note = "Please use ::jws::alg::HS384")]
pub use crate::jws::alg::hmac::HmacJwsAlgorithm::HS384;
#[deprecated(since = "0.4.0", note = "Please use ::jws::alg::HS512")]
pub use crate::jws::alg::hmac::HmacJwsAlgorithm::HS512;

#[deprecated(since = "0.4.0", note = "Please use ::jws::alg::RS256")]
pub use crate::jws::alg::rsassa::RsassaJwsAlgorithm::RS256;
#[deprecated(since = "0.4.0", note = "Please use ::jws::alg::RS384")]
pub use crate::jws::alg::rsassa::RsassaJwsAlgorithm::RS384;
#[deprecated(since = "0.4.0", note = "Please use ::jws::alg::RS512")]
pub use crate::jws::alg::rsassa::RsassaJwsAlgorithm::RS512;

#[deprecated(since = "0.4.0", note = "Please use ::jws::alg::PS256")]
pub use crate::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm::PS256;
#[deprecated(since = "0.4.0", note = "Please use ::jws::alg::PS384")]
pub use crate::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm::PS384;
#[deprecated(since = "0.4.0", note = "Please use ::jws::alg::PS512")]
pub use crate::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm::PS512;

#[deprecated(since = "0.4.0", note = "Please use ::jws::alg::ES256")]
pub use crate::jws::alg::ecdsa::EcdsaJwsAlgorithm::ES256;
#[deprecated(since = "0.4.0", note = "Please use ::jws::alg::ES256K")]
pub use crate::jws::alg::ecdsa::EcdsaJwsAlgorithm::ES256K;
#[deprecated(since = "0.4.0", note = "Please use ::jws::alg::ES384")]
pub use crate::jws::alg::ecdsa::EcdsaJwsAlgorithm::ES384;
#[deprecated(since = "0.4.0", note = "Please use ::jws::alg::ES512")]
pub use crate::jws::alg::ecdsa::EcdsaJwsAlgorithm::ES512;

#[deprecated(since = "0.4.0", note = "Please use ::jws::alg::EdDSA")]
pub use crate::jws::alg::eddsa::EddsaJwsAlgorithm::EdDSA;

static DEFAULT_CONTEXT: Lazy<JwsContext> = Lazy::new(|| JwsContext::new());

/// Return a representation of the data that is formatted by compact serialization.
///
/// # Arguments
///
/// * `payload` - The payload data.
/// * `header` - The JWS heaser claims.
/// * `signer` - The JWS signer.
pub fn serialize_compact(
    payload: &[u8],
    header: &JwsHeader,
    signer: &dyn JwsSigner,
) -> Result<String, JoseError> {
    DEFAULT_CONTEXT.serialize_compact(payload, header, signer)
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
    header: &JwsHeader,
    selector: F,
) -> Result<String, JoseError>
where
    F: Fn(&JwsHeader) -> Option<&'a dyn JwsSigner>,
{
    DEFAULT_CONTEXT.serialize_compact_with_selector(payload, header, selector)
}

/// Return a representation of the data that is formatted by flattened json serialization.
///
/// # Arguments
///
/// * `protected` - The JWS protected header claims.
/// * `header` - The JWS unprotected header claims.
/// * `payload` - The payload data.
/// * `signer` - The JWS signer.
pub fn serialize_general_json(
    payload: &[u8],
    signer: &JwsMultiSigner,
) -> Result<String, JoseError> {
    DEFAULT_CONTEXT.serialize_general_json(payload, signer)
}

/// Return a representation of the data that is formatted by flattened json serialization.
///
/// # Arguments
///
/// * `payload` - The payload data.
/// * `protected` - The JWS protected header claims.
/// * `header` - The JWS unprotected header claims.
/// * `signer` - The JWS signer.
pub fn serialize_flattened_json(
    payload: &[u8],
    protected: Option<&JwsHeader>,
    header: Option<&JwsHeader>,
    signer: &dyn JwsSigner,
) -> Result<String, JoseError> {
    DEFAULT_CONTEXT.serialize_flattened_json(payload, protected, header, signer)
}

/// Return a representation of the data that is formatted by flatted json serialization.
///
/// # Arguments
///
/// * `payload` - The payload data.
/// * `protected` - The JWS protected header claims.
/// * `header` - The JWS unprotected header claims.
/// * `selector` - a function for selecting the signing algorithm.
pub fn serialize_flattened_json_with_selector<'a, F>(
    payload: &[u8],
    protected: Option<&JwsHeader>,
    header: Option<&JwsHeader>,
    selector: F,
) -> Result<String, JoseError>
where
    F: Fn(&JwsHeader) -> Option<&'a dyn JwsSigner>,
{
    DEFAULT_CONTEXT.serialize_flattened_json_with_selector(payload, protected, header, selector)
}

/// Deserialize the input that is formatted by compact serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `header` - The decoded JWS header claims.
/// * `verifier` - The JWS verifier.
pub fn deserialize_compact(
    input: &str,
    verifier: &dyn JwsVerifier,
) -> Result<(Vec<u8>, JwsHeader), JoseError> {
    DEFAULT_CONTEXT.deserialize_compact(input, verifier)
}

/// Deserialize the input that is formatted by compact serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `header` - The decoded JWS header claims.
/// * `selector` - a function for selecting the verifying algorithm.
pub fn deserialize_compact_with_selector<'a, F>(
    input: &str,
    selector: F,
) -> Result<(Vec<u8>, JwsHeader), JoseError>
where
    F: Fn(&JwsHeader) -> Result<Option<&'a dyn JwsVerifier>, JoseError>,
{
    DEFAULT_CONTEXT.deserialize_compact_with_selector(input, selector)
}

/// Deserialize the input that is formatted by json serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `header` - The decoded JWS header claims.
/// * `verifier` - The JWS verifier.
pub fn deserialize_json<'a>(
    input: &str,
    verifier: &'a dyn JwsVerifier,
) -> Result<(Vec<u8>, JwsHeader), JoseError> {
    DEFAULT_CONTEXT.deserialize_json(input, verifier)
}

/// Deserialize the input that is formatted by json serialization.
///
/// # Arguments
///
/// * `input` - The input data.
/// * `header` - The decoded JWS header claims.
/// * `selector` - a function for selecting the verifying algorithm.
pub fn deserialize_json_with_selector<'a, F>(
    input: &str,
    selector: F,
) -> Result<(Vec<u8>, JwsHeader), JoseError>
where
    F: Fn(&JwsHeader) -> Result<Option<&'a dyn JwsVerifier>, JoseError>,
{
    DEFAULT_CONTEXT.deserialize_json_with_selector(input, selector)
}

#[cfg(test)]
mod tests {
    use crate::jws::{self, EdDSA, JwsHeader, JwsMultiSigner, ES256, RS256};
    use anyhow::Result;
    use serde_json::Value;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;

    #[test]
    fn test_jws_compact_serialization() -> Result<()> {
        let alg = RS256;

        let private_key = load_file("pem/RSA_2048bit_private.pem")?;
        let public_key = load_file("pem/RSA_2048bit_public.pem")?;

        let mut src_header = JwsHeader::new();
        src_header.set_token_type("JWT");
        let src_payload = b"test payload!";
        let signer = alg.signer_from_pem(&private_key)?;
        let jwt = jws::serialize_compact(src_payload, &src_header, &signer)?;

        let verifier = alg.verifier_from_pem(&public_key)?;
        let (dst_payload, dst_header) = jws::deserialize_compact(&jwt, &verifier)?;

        src_header.set_claim("alg", Some(Value::String(alg.name().to_string())))?;
        assert_eq!(src_header, dst_header);
        assert_eq!(src_payload.to_vec(), dst_payload);

        Ok(())
    }

    #[test]
    fn test_jws_json_serialization() -> Result<()> {
        let alg = RS256;

        let private_key = load_file("pem/RSA_2048bit_private.pem")?;
        let public_key = load_file("pem/RSA_2048bit_public.pem")?;

        let src_payload = b"test payload!";
        let mut src_protected = JwsHeader::new();
        src_protected.set_key_id("xxx");
        let mut src_header = JwsHeader::new();
        src_header.set_token_type("JWT");
        let signer = alg.signer_from_pem(&private_key)?;
        let jwt = jws::serialize_flattened_json(
            src_payload,
            Some(&src_protected),
            Some(&src_header),
            &signer,
        )?;

        let verifier = alg.verifier_from_pem(&public_key)?;
        let (dst_payload, dst_header) = jws::deserialize_json(&jwt, &verifier)?;

        src_header.set_claim("alg", Some(Value::String(alg.name().to_string())))?;
        assert_eq!(src_protected.key_id(), dst_header.key_id());
        assert_eq!(src_header.token_type(), dst_header.token_type());
        assert_eq!(src_payload.to_vec(), dst_payload);

        Ok(())
    }

    #[test]
    fn test_jws_general_json_serialization() -> Result<()> {
        let private_key_1 = load_file("pem/RSA_2048bit_private.pem")?;
        let private_key_2 = load_file("pem/EC_P-256_private.pem")?;
        let private_key_3 = load_file("pem/ED25519_private.pem")?;

        let public_key = load_file("pem/EC_P-256_public.pem")?;

        let src_payload = b"test payload!";

        let mut src_protected_1 = JwsHeader::new();
        src_protected_1.set_key_id("xxx-1");
        let mut src_header_1 = JwsHeader::new();
        src_header_1.set_token_type("JWT-1");
        let signer_1 = RS256.signer_from_pem(&private_key_1)?;

        let mut src_protected_2 = JwsHeader::new();
        src_protected_2.set_key_id("xxx-2");
        let mut src_header_2 = JwsHeader::new();
        src_header_2.set_token_type("JWT-2");
        let signer_2 = ES256.signer_from_pem(&private_key_2)?;

        let mut src_protected_3 = JwsHeader::new();
        src_protected_3.set_key_id("xxx-3");
        let mut src_header_3 = JwsHeader::new();
        src_header_3.set_token_type("JWT-3");
        let signer_3 = EdDSA.signer_from_pem(&private_key_3)?;

        let mut multi_signer = JwsMultiSigner::new();
        multi_signer.add_signer(Some(&src_protected_1), Some(&src_header_1), &signer_1)?;
        multi_signer.add_signer(Some(&src_protected_2), Some(&src_header_2), &signer_2)?;
        multi_signer.add_signer(Some(&src_protected_3), Some(&src_header_3), &signer_3)?;

        let json = jws::serialize_general_json(src_payload, &multi_signer)?;

        let verifier = ES256.verifier_from_pem(&public_key)?;
        let (dst_payload, dst_header) = jws::deserialize_json(&json, &verifier)?;

        assert_eq!(dst_header.algorithm(), Some("ES256"));
        assert_eq!(src_protected_2.key_id(), dst_header.key_id());
        assert_eq!(src_header_2.token_type(), dst_header.token_type());
        assert_eq!(src_payload.to_vec(), dst_payload);

        Ok(())
    }

    fn load_file(path: &str) -> Result<Vec<u8>> {
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push("data");
        pb.push(path);

        let mut file = File::open(&pb)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(data)
    }
}

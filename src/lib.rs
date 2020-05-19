//! # JWT-RS
//! 
//! `jwt_rs` is a JWT (JSON Web Token) library (based on OpenSSL).
pub mod algorithm;
pub mod error;

use std::time::{Duration, SystemTime};

use anyhow::bail;
use serde_json::Map;

use crate::algorithm::hmac::HmacAlgorithm;
use crate::algorithm::rsa::RsaAlgorithm;
use crate::algorithm::ecdsa::EcdsaAlgorithm;
use crate::algorithm::rsapss::RsaPssAlgorithm;
use crate::algorithm::{Algorithm, HashAlgorithm, Signer, Verifier};
use crate::error::JwtError;

/// HMAC using SHA-256
pub const HS256: HmacAlgorithm = HmacAlgorithm::new(HashAlgorithm::SHA256);

/// HMAC using SHA-384
pub const HS384: HmacAlgorithm = HmacAlgorithm::new(HashAlgorithm::SHA384);

/// HMAC using SHA-512
pub const HS512: HmacAlgorithm = HmacAlgorithm::new(HashAlgorithm::SHA512);

/// RSASSA-PKCS1-v1_5 using SHA-256
pub const RS256: RsaAlgorithm = RsaAlgorithm::new(HashAlgorithm::SHA256);

/// RSASSA-PKCS1-v1_5 using SHA-384
pub const RS384: RsaAlgorithm = RsaAlgorithm::new(HashAlgorithm::SHA384);

/// RSASSA-PKCS1-v1_5 using SHA-512
pub const RS512: RsaAlgorithm = RsaAlgorithm::new(HashAlgorithm::SHA512);

/// ECDSA using P-256 and SHA-256
pub const ES256: EcdsaAlgorithm = EcdsaAlgorithm::new(HashAlgorithm::SHA256);

/// ECDSA using P-384 and SHA-384
pub const ES384: EcdsaAlgorithm = EcdsaAlgorithm::new(HashAlgorithm::SHA384);

/// ECDSA using P-521 and SHA-512
pub const ES512: EcdsaAlgorithm = EcdsaAlgorithm::new(HashAlgorithm::SHA512);

/// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
pub const PS256: RsaPssAlgorithm = RsaPssAlgorithm::new(HashAlgorithm::SHA256);

/// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
pub const PS384: RsaPssAlgorithm = RsaPssAlgorithm::new(HashAlgorithm::SHA384);

/// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
pub const PS512: RsaPssAlgorithm = RsaPssAlgorithm::new(HashAlgorithm::SHA512);

/// Represents any valid JSON value.
///
/// See the `serde_json::value` module documentation for usage examples.
pub type Value = serde_json::Value;

/// Represents plain JWT object with header and payload.
#[derive(Debug, Eq, PartialEq)]
pub struct Jwt {
    header: Map<String, Value>,
    payload: Map<String, Value>,
}

impl Jwt {
    /// Return a new JWT object that has only a typ="JWT" header claim.
    pub fn new() -> Self {
        let mut header = Map::new();
        header.insert("typ".to_string(), Value::String("JWT".to_string()));

        Self {
            header,
            payload: Map::new(),
        }
    }
/*
    /// Return a JWT object that is decoded the input with a selected algorithm by a selector.
    ///
    /// # Arguments
    /// * `input` - JWT text.
    /// * `selector` - Verifier selector.
    pub fn decode<T: Algorithm, F>(input: &str, selector: F) -> Result<Self, JwtError> 
        where F: FnMut(mut header: Map<String, Value>) -> Box<&dyn Verifier<T>>
    {
        let (
            header,
            payload,
            data,
            signature,
            verifier
        ) = (|| -> anyhow::Result<(
            Map<String, Value>,
            Map<String, Value>,
            [&[u8]; 3],
            Vec<u8>,
            Box<&dyn Verifier<T>>
        )> {
            let parts: Vec<&str> = input.split('.').collect();
            if parts.len() != 3 {
                bail!("JWT must be three parts separated by colon.");
            }

            let header_base64 = parts.get(0).unwrap();

            let header_json = base64::decode_config(header_base64, base64::URL_SAFE_NO_PAD)?;
            let mut header: Map<String, Value> = serde_json::from_slice(&header_json)?;

            let verifier = selector(mut header);

            if let Some(Value::String(expected_alg)) = header.remove("alg") {
                let actual_alg = verifier.algorithm().name();
                if expected_alg != actual_alg {
                    bail!("JWT alg header parameter is mismatched: expected = {}, actual = {}", &expected_alg, &actual_alg);
                }
            } else {
                bail!("JWT alg header parameter is missing.");
            }

            let payload_base64 = parts.get(1).unwrap();
            let payload_json = base64::decode_config(payload_base64, base64::URL_SAFE_NO_PAD)?;
            let payload: Map<String, Value> = serde_json::from_slice(&payload_json)?;

            let signature_base64 = parts.get(2).unwrap();
            let signature = base64::decode_config(signature_base64, base64::URL_SAFE_NO_PAD)?;

            Ok((
                header,
                payload,
                [header_base64.as_bytes(), b".", payload_base64.as_bytes()],
                signature,
                verifier
            ))
        })()
            .map_err(|err| JwtError::InvalidJwtFormat(err))?;

        verifier.verify(&data, &signature)?;

        Ok(Jwt { header, payload })
    }
*/
    /// Return a JWT object that is decoded the input with a "none" algorithm.
    ///
    /// # Arguments
    ///
    /// * `input` - JWT text.
    pub fn decode_with_none(input: &str) -> Result<Self, JwtError> {
        (|| -> anyhow::Result<Self> {
            let parts: Vec<&str> = input.split('.').collect();
            if parts.len() != 2 {
                bail!("JWT must be two parts separated by colon.");
            }

            let header_base64 = parts.get(0).unwrap();
            let header_json = base64::decode_config(header_base64, base64::URL_SAFE_NO_PAD)?;
            let mut header: Map<String, Value> = serde_json::from_slice(&header_json)?;

            if let Some(Value::String(expected_alg)) = header.remove("alg") {
                let actual_alg = "none".to_string();
                if expected_alg != actual_alg {
                    bail!(
                        "JWT alg header parameter is mismatched: expected = {}, actual = {}",
                        &expected_alg,
                        &actual_alg
                    );
                }
            } else {
                bail!("JWT alg header parameter is missing.");
            }

            let payload_base64 = parts.get(1).unwrap();
            let payload_json = base64::decode_config(payload_base64, base64::URL_SAFE_NO_PAD)?;
            let payload: Map<String, Value> = serde_json::from_slice(&payload_json)?;

            Ok(Jwt { header, payload })
        })()
            .map_err(|err| JwtError::InvalidJwtFormat(err))
    }

    /// Return a JWT Object that is decoded the input with a signing algorithm.
    ///
    /// # Arguments
    ///
    /// * `input` - JWT text.
    /// * `verifier` - A verifier of the siging algorithm.
    pub fn decode_with_verifier<T: Algorithm>(
        input: &str,
        verifier: &impl Verifier<T>,
    ) -> Result<Self, JwtError> {
        (|| -> anyhow::Result<Result<Jwt, JwtError>> {
            let parts: Vec<&str> = input.split('.').collect();
            if parts.len() != 3 {
                bail!("JWT must be three parts separated by colon.");
            }

            let header_base64 = parts.get(0).unwrap();

            let header_json = base64::decode_config(header_base64, base64::URL_SAFE_NO_PAD)?;
            let mut header: Map<String, Value> = serde_json::from_slice(&header_json)?;

            if let Some(Value::String(expected_alg)) = header.remove("alg") {
                let actual_alg = verifier.algorithm().name();
                if expected_alg != actual_alg {
                    bail!("JWT alg header parameter is mismatched: expected = {}, actual = {}", &expected_alg, &actual_alg);
                }
            } else {
                bail!("JWT alg header parameter is missing.");
            }

            let payload_base64 = parts.get(1).unwrap();
            let payload_json = base64::decode_config(payload_base64, base64::URL_SAFE_NO_PAD)?;
            let payload: Map<String, Value> = serde_json::from_slice(&payload_json)?;

            let signature_base64 = parts.get(2).unwrap();
            let signature = base64::decode_config(signature_base64, base64::URL_SAFE_NO_PAD)?;

            Ok(verifier
                .verify(&[header_base64.as_bytes(), b".", payload_base64.as_bytes()], &signature)
                .map(|_| Jwt { header, payload }))
        })()
            .map_err(|err| JwtError::InvalidJwtFormat(err))?
    }

    /// Return a JWT Object that is decoded the input with a signing algorithm.
    ///
    /// # Arguments
    ///
    /// * `input` - JWT text.
    /// * `verifier` - A verifier of the siging algorithm.
    pub fn decode_with_selected_verifier<T: Algorithm>(
        input: &str,
        verifier: &impl Verifier<T>,
    ) -> Result<Self, JwtError> {
        (|| -> anyhow::Result<Result<Jwt, JwtError>> {
            let parts: Vec<&str> = input.split('.').collect();
            if parts.len() != 3 {
                bail!("JWT must be three parts separated by colon.");
            }

            let header_base64 = parts.get(0).unwrap();

            let header_json = base64::decode_config(header_base64, base64::URL_SAFE_NO_PAD)?;
            let mut header: Map<String, Value> = serde_json::from_slice(&header_json)?;

            if let Some(Value::String(expected_alg)) = header.remove("alg") {
                let actual_alg = verifier.algorithm().name();
                if expected_alg != actual_alg {
                    bail!("JWT alg header parameter is mismatched: expected = {}, actual = {}", &expected_alg, &actual_alg);
                }
            } else {
                bail!("JWT alg header parameter is missing.");
            }

            let payload_base64 = parts.get(1).unwrap();
            let payload_json = base64::decode_config(payload_base64, base64::URL_SAFE_NO_PAD)?;
            let payload: Map<String, Value> = serde_json::from_slice(&payload_json)?;

            let signature_base64 = parts.get(2).unwrap();
            let signature = base64::decode_config(signature_base64, base64::URL_SAFE_NO_PAD)?;

            Ok(verifier
                .verify(&[header_base64.as_bytes(), b".", payload_base64.as_bytes()], &signature)
                .map(|_| Jwt { header, payload }))
        })()
            .map_err(|err| JwtError::InvalidJwtFormat(err))?
    }

    /// Set a value for token type header claim (typ).
    ///
    /// # Arguments
    /// * `token_type` - A token type (e.g. "JWT")
    pub fn set_token_type(mut self, token_type: &str) -> Self {
        self.header
            .insert("typ".to_string(), Value::String(token_type.to_string()));
        self
    }

    /// Return a value for token type header claim (typ).
    pub fn token_type(&self) -> Option<&str> {
        match self.header.get("typ") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for content type header claim (cty).
    ///
    /// # Arguments
    /// * `content_type` - A content type (e.g. "JWT")
    pub fn set_content_type(mut self, content_type: &str) -> Self {
        self.header
            .insert("cty".to_string(), Value::String(content_type.to_string()));
        self
    }

    /// Return a value for content type header claim (cty).
    pub fn content_type(&self) -> Option<&str> {
        match self.header.get("cty") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for content type header claim (kid).
    ///
    /// # Arguments
    /// * `key_id` - A key ID
    pub fn set_key_id(mut self, key_id: &str) -> Self {
        self.header
            .insert("kid".to_string(), Value::String(key_id.to_string()));
        self
    }

    /// Return a value for key ID header claim (kid).
    pub fn key_id(&self) -> Option<&str> {
        match self.header.get("kid") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for a header claim of a specified key.
    ///
    /// # Arguments
    /// * `key` - A key name of a header claim
    /// * `value` - A typed value of a header claim
    pub fn set_header_claim(mut self, key: &str, value: &Value) -> Self {
        self.header.insert(key.to_string(), (*value).clone());
        self
    }

    /// Return a value for a header claim of a specified key.
    ///
    /// # Arguments
    /// * `key` - A key name of a header claim
    pub fn header_claim(&self, key: &str) -> Option<&Value> {
        self.header.get(key)
    }

    /// Unset a value for a header claim of a specified key.
    ///
    /// # Arguments
    /// * `key` - A key name of a header claim
    pub fn unset_header_claim(mut self, key: &str) -> Self {
        self.header.remove(key);
        self
    }

    /// Set a value for a issuer payload claim (iss).
    ///
    /// # Arguments
    /// * `issuer` - A issuer
    pub fn set_issuer(mut self, issuer: &str) -> Self {
        self.payload
            .insert("iss".to_string(), Value::String(issuer.to_string()));
        self
    }

    /// Return a value for a issuer payload claim (iss).
    pub fn issuer(&self) -> Option<&str> {
        match self.payload.get("iss") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for a subject payload claim (sub).
    ///
    /// # Arguments
    /// * `subject` - A subject
    pub fn set_subject<'a>(mut self, subject: &str) -> Self {
        self.payload
            .insert("sub".to_string(), Value::String(subject.to_string()));
        self
    }

    /// Return a value for a subject payload claim (sub).
    pub fn subject(&self) -> Option<&str> {
        match self.payload.get("sub") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for a audience payload claim (aud).
    ///
    /// # Arguments
    /// * `subject` - A audience
    pub fn set_audience(mut self, audience: &str) -> Self {
        self.payload
            .insert("aud".to_string(), Value::String(audience.to_string()));
        self
    }

    /// Return a value for a audience payload claim (sub).
    pub fn audience(&self) -> Option<&str> {
        match self.payload.get("aud") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a system time for a expires at payload claim (exp).
    ///
    /// # Arguments
    /// * `expires_at` - The expiration time on or after which the JWT must not be accepted for processing.
    pub fn set_expires_at(mut self, expires_at: &SystemTime) -> Self {
        self.payload.insert(
            "exp".to_string(),
            Value::Number(
                expires_at
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .into(),
            ),
        );
        self
    }

    /// Return a system time for a expires at payload claim (exp).
    pub fn expires_at(&self) -> Option<SystemTime> {
        match self.payload.get("exp") {
            Some(Value::Number(val)) => match val.as_u64() {
                Some(val) => Some(SystemTime::UNIX_EPOCH + Duration::from_secs(val)),
                _ => None,
            },
            _ => None,
        }
    }

    /// Set a system time for a not before payload claim (nbf).
    ///
    /// # Arguments
    /// * `not_before` - The time before which the JWT must not be accepted for processing.
    pub fn set_not_before(mut self, not_before: &SystemTime) -> Self {
        self.payload.insert(
            "nbf".to_string(),
            Value::Number(
                not_before
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .into(),
            ),
        );
        self
    }

    /// Return a system time for a not before payload claim (nbf).
    pub fn not_before(&self) -> Option<SystemTime> {
        match self.payload.get("nbf") {
            Some(Value::Number(val)) => match val.as_u64() {
                Some(val) => Some(SystemTime::UNIX_EPOCH + Duration::from_secs(val)),
                _ => None,
            },
            _ => None,
        }
    }

    /// Set a time for a issued at payload claim (iat).
    ///
    /// # Arguments
    /// * `issued_at` - The time at which the JWT was issued.
    pub fn set_issued_at(mut self, issued_at: &SystemTime) -> Self {
        self.payload.insert(
            "iat".to_string(),
            Value::Number(
                issued_at
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .into(),
            ),
        );
        self
    }

    /// Return a time for a issued at payload claim (iat).
    pub fn issued_at(&self) -> Option<SystemTime> {
        match self.payload.get("iat") {
            Some(Value::Number(val)) => match val.as_u64() {
                Some(val) => Some(SystemTime::UNIX_EPOCH + Duration::from_secs(val)),
                _ => None,
            },
            _ => None,
        }
    }

    /// Set a value for a jwt id payload claim (jti).
    ///
    /// # Arguments
    /// * `jwt_id` - A jwt id
    pub fn set_jwt_id(mut self, jwt_id: &str) -> Self {
        self.payload
            .insert("jti".to_string(), Value::String(jwt_id.to_string()));
        self
    }

    /// Return a value for a jwt id payload claim (jti).
    pub fn jwt_id(&self) -> Option<&str> {
        match self.payload.get("jti") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for a payload claim of a specified key.
    ///
    /// # Arguments
    /// * `key` - A key name of a payload claim
    /// * `value` - A typed value of a payload claim
    pub fn set_payload_claim(mut self, key: &str, value: &Value) -> Self {
        self.payload.insert(key.to_string(), (*value).clone());
        self
    }

    /// Return a value for a payload claim of a specified key.
    ///
    /// # Arguments
    /// * `key` - A key name of a payload claim
    pub fn payload_claim(&self, key: &str) -> Option<&Value> {
        self.payload.get(key)
    }

    /// Unset a value for a payload claim of a specified key.
    ///
    /// # Arguments
    /// * `key` - A key name of a payload claim
    pub fn unset_payload_claim(mut self, key: &str) -> Self {
        self.payload.remove(key);
        self
    }

    /// Return a JWT text that is decoded with a "none" algorithm.
    pub fn encode_with_none(&self) -> Result<String, JwtError> {
        let mut header = self.header.clone();
        header.insert("alg".to_string(), Value::String("none".to_string()));

        let header_json = serde_json::to_string(&header).unwrap();
        let header_base64 = base64::encode_config(header_json, base64::URL_SAFE_NO_PAD);

        let payload_json = serde_json::to_string(&self.payload).unwrap();
        let payload_base64 = base64::encode_config(payload_json, base64::URL_SAFE_NO_PAD);

        Ok(format!("{}.{}", header_base64, payload_base64))
    }

    /// Return a JWT text that is encoded with a signing algorithm.
    ///
    /// # Arguments
    ///
    /// * `signer` - A signer of the siging algorithm.
    pub fn encode_with_signer<T: Algorithm>(
        &self,
        signer: &impl Signer<T>,
    ) -> Result<String, JwtError> {
        let name = signer.algorithm().name();

        let mut header = self.header.clone();
        header.insert("alg".to_string(), Value::String(name.to_string()));

        let header_json = serde_json::to_string(&header).unwrap();
        let header_base64 = base64::encode_config(header_json, base64::URL_SAFE_NO_PAD);

        let payload_json = serde_json::to_string(&self.payload).unwrap();
        let payload_base64 = base64::encode_config(payload_json, base64::URL_SAFE_NO_PAD);

        let signature =
            signer.sign(&[header_base64.as_bytes(), b".", payload_base64.as_bytes()])?;

        let signature_base64 = base64::encode_config(signature, base64::URL_SAFE_NO_PAD);
        Ok(format!(
            "{}.{}.{}",
            header_base64, payload_base64, signature_base64
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Result;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;

    #[test]
    fn test_jwt_with_none() -> Result<()> {
        let from_jwt = Jwt::new();

        let jwt_string = from_jwt.encode_with_none()?;
        let to_jwt = Jwt::decode_with_none(&jwt_string)?;

        assert_eq!(from_jwt, to_jwt);

        Ok(())
    }

    #[test]
    fn test_jwt_with_hmac() -> Result<()> {
        let from_jwt = Jwt::new();

        for alg in &[HS256, HS384, HS512] {
            let private_key = b"quety12389";
            let signer = alg.signer_from_bytes(private_key)?;
            let jwt_string = from_jwt.encode_with_signer(&signer)?;

            let to_jwt = Jwt::decode_with_verifier(&jwt_string, &signer)?;

            assert_eq!(from_jwt, to_jwt);
        }

        Ok(())
    }

    #[test]
    fn test_jwt_with_rsa_pem() -> Result<()> {
        let from_jwt = Jwt::new();

        for alg in &[RS256, RS384, RS512] {
            let private_key = load_file("keys/rsa_2048_private.pem")?;
            let signer = alg.signer_from_private_pem(&private_key)?;
            let jwt_string = from_jwt.encode_with_signer(&signer)?;

            let public_key = load_file("keys/rsa_2048_public.pem")?;
            let verifier = alg.verifier_from_public_pem(&public_key)?;
            let to_jwt = Jwt::decode_with_verifier(&jwt_string, &verifier)?;

            assert_eq!(from_jwt, to_jwt);
        }

        Ok(())
    }

    #[test]
    fn test_jwt_with_rsa_der() -> Result<()> {
        let from_jwt = Jwt::new();

        for alg in &[RS256, RS384, RS512] {
            let private_key = load_file("keys/rsa_2048_private.der")?;
            let signer = alg.signer_from_private_der(&private_key)?;
            let jwt_string = from_jwt.encode_with_signer(&signer)?;

            let public_key = load_file("keys/rsa_2048_public.der")?;
            let verifier = alg.verifier_from_public_der(&public_key)?;
            let to_jwt = Jwt::decode_with_verifier(&jwt_string, &verifier)?;

            assert_eq!(from_jwt, to_jwt);
        }

        Ok(())
    }

    #[test]
    fn test_jwt_with_ecdsa_pem() -> Result<()> {
        let from_jwt = Jwt::new();

        for alg in &[ES256, ES384, ES512] {
            let curve_name = curve_name(alg.name());

            let private_key = load_file(&format!("keys/ecdsa_{}_private.pem", curve_name))?;
            let public_key = load_file(&format!("keys/ecdsa_{}_public.pem", curve_name))?;

            let signer = alg.signer_from_private_pem(&private_key)?;
            let jwt_string = from_jwt.encode_with_signer(&signer)?;

            let verifier = alg.verifier_from_public_pem(&public_key)?;
            let to_jwt = Jwt::decode_with_verifier(&jwt_string, &verifier)?;

            assert_eq!(from_jwt, to_jwt);
        }

        Ok(())
    }

    #[test]
    fn test_jwt_with_ecdsa_der() -> Result<()> {
        let from_jwt = Jwt::new();

        for alg in &[ES256, ES384, ES512] {
            let curve_name = curve_name(alg.name());

            let private_key = load_file(&format!("keys/ecdsa_{}_private.der", curve_name))?;
            let public_key = load_file(&format!("keys/ecdsa_{}_public.der", curve_name))?;

            let signer = alg.signer_from_private_der(&private_key)?;
            let jwt_string = from_jwt.encode_with_signer(&signer)?;

            let verifier = alg.verifier_from_public_der(&public_key)?;
            let to_jwt = Jwt::decode_with_verifier(&jwt_string, &verifier)?;

            assert_eq!(from_jwt, to_jwt);
        }

        Ok(())
    }

    fn curve_name(name: &str) -> &'static str {
        match name {
            "ES256" => "p256",
            "ES384" => "p384",
            "ES512" => "p521",
            _ => unreachable!()
        }
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

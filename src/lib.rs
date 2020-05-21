//! # JWT-RS
//!
//! `jwt_rs` is a JWT (JSON Web Token) library (based on OpenSSL).
pub mod algorithm;
pub mod error;

use std::time::{Duration, SystemTime};

use anyhow::bail;
use serde_json::map::Entry;
use serde_json::{json, Map};

use crate::algorithm::ecdsa::EcdsaAlgorithm;
use crate::algorithm::hmac::HmacAlgorithm;
use crate::algorithm::rsa::RsaAlgorithm;
use crate::algorithm::{Algorithm, HashAlgorithm, Signer, Verifier};
use crate::error::JwtError;

/// HMAC using SHA-256
pub const HS256: HmacAlgorithm = HmacAlgorithm::new("HS256", HashAlgorithm::SHA256);

/// HMAC using SHA-384
pub const HS384: HmacAlgorithm = HmacAlgorithm::new("HS384", HashAlgorithm::SHA384);

/// HMAC using SHA-512
pub const HS512: HmacAlgorithm = HmacAlgorithm::new("HS512", HashAlgorithm::SHA512);

/// RSASSA-PKCS1-v1_5 using SHA-256
pub const RS256: RsaAlgorithm = RsaAlgorithm::new("RS256", HashAlgorithm::SHA256);

/// RSASSA-PKCS1-v1_5 using SHA-384
pub const RS384: RsaAlgorithm = RsaAlgorithm::new("RS384", HashAlgorithm::SHA384);

/// RSASSA-PKCS1-v1_5 using SHA-512
pub const RS512: RsaAlgorithm = RsaAlgorithm::new("RS512", HashAlgorithm::SHA512);

/// ECDSA using P-256 and SHA-256
pub const ES256: EcdsaAlgorithm = EcdsaAlgorithm::new("ES256", HashAlgorithm::SHA256);

/// ECDSA using P-384 and SHA-384
pub const ES384: EcdsaAlgorithm = EcdsaAlgorithm::new("ES384", HashAlgorithm::SHA384);

/// ECDSA using P-521 and SHA-512
pub const ES512: EcdsaAlgorithm = EcdsaAlgorithm::new("ES512", HashAlgorithm::SHA512);

/// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
pub const PS256: RsaAlgorithm = RsaAlgorithm::new("PS256", HashAlgorithm::SHA256);

/// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
pub const PS384: RsaAlgorithm = RsaAlgorithm::new("PS384", HashAlgorithm::SHA384);

/// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
pub const PS512: RsaAlgorithm = RsaAlgorithm::new("PS512", HashAlgorithm::SHA512);

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
        header.insert("typ".to_string(), json!("JWT"));

        Self {
            header,
            payload: Map::new(),
        }
    }

    /// Return a JWT object that is decoded the input with a "none" algorithm.
    ///
    /// # Arguments
    /// * `input` - JWT text.
    pub fn decode_with_none(input: &str) -> Result<Self, JwtError> {
        (|| -> anyhow::Result<Self> {
            let parts: Vec<&str> = input.split('.').collect();
            if parts.len() != 2 {
                bail!("JWT must be two parts separated by colon.");
            }

            let header_base64 = parts.get(0).unwrap();
            let header_json = base64::decode_config(header_base64, base64::URL_SAFE_NO_PAD)?;
            let header: Map<String, Value> = serde_json::from_slice(&header_json)?;

            let payload_base64 = parts.get(1).unwrap();
            let payload_json = base64::decode_config(payload_base64, base64::URL_SAFE_NO_PAD)?;
            let payload: Map<String, Value> = serde_json::from_slice(&payload_json)?;

            let jwt = Jwt { header, payload };

            if let Some(expected_alg) = jwt.algorithm() {
                let actual_alg = "none";
                if expected_alg != actual_alg {
                    bail!(
                        "JWT alg header parameter is mismatched: expected = {}, actual = {}",
                        expected_alg,
                        actual_alg
                    );
                }
            } else {
                bail!("JWT alg header parameter is missing.");
            }

            Ok(jwt)
        })()
        .map_err(|err| JwtError::InvalidJwtFormat(err))
    }

    /// Return a JWT Object that is decoded the input with a signing algorithm.
    ///
    /// # Arguments
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
            let header: Map<String, Value> = serde_json::from_slice(&header_json)?;

            let payload_base64 = parts.get(1).unwrap();
            let payload_json = base64::decode_config(payload_base64, base64::URL_SAFE_NO_PAD)?;
            let payload: Map<String, Value> = serde_json::from_slice(&payload_json)?;

            let jwt = Jwt { header, payload };

            if let Some(expected_alg) = jwt.algorithm() {
                let actual_alg = verifier.algorithm().name();
                if expected_alg != actual_alg {
                    bail!(
                        "JWT alg header parameter is mismatched: expected = {}, actual = {}",
                        expected_alg,
                        actual_alg
                    );
                }
            } else {
                bail!("JWT alg header parameter is missing.");
            }

            let signature_base64 = parts.get(2).unwrap();
            let signature = base64::decode_config(signature_base64, base64::URL_SAFE_NO_PAD)?;

            Ok(verifier
                .verify(
                    &[header_base64.as_bytes(), b".", payload_base64.as_bytes()],
                    &signature,
                )
                .map(|_| jwt))
        })()
        .map_err(|err| JwtError::InvalidJwtFormat(err))?
    }

    /// Return a JWT Object that is decoded the input with a signing algorithm.
    ///
    /// # Arguments
    /// * `input` - JWT text.
    /// * `verifier_selector` - A function for selecting the siging algorithm.
    pub fn decode_with_verifier_selector<'a, T, F>(
        input: &str,
        verifier_selector: F,
    ) -> Result<Self, JwtError>
    where
        T: Algorithm + 'a,
        F: FnOnce(&Jwt) -> Box<&'a dyn Verifier<T>>,
    {
        (|| -> anyhow::Result<Result<Jwt, JwtError>> {
            let parts: Vec<&str> = input.split('.').collect();
            if parts.len() != 2 && parts.len() != 3 {
                bail!("JWT must be two or three parts separated by colon.");
            }

            let header_base64 = parts.get(0).unwrap();
            let header_json = base64::decode_config(header_base64, base64::URL_SAFE_NO_PAD)?;
            let header: Map<String, Value> = serde_json::from_slice(&header_json)?;

            let payload_base64 = parts.get(1).unwrap();
            let payload_json = base64::decode_config(payload_base64, base64::URL_SAFE_NO_PAD)?;
            let payload: Map<String, Value> = serde_json::from_slice(&payload_json)?;

            let jwt = Jwt { header, payload };

            let alg = match jwt.algorithm() {
                Some(alg) if alg == "none" => {
                    if parts.len() != 2 {
                        bail!("JWT must not have signature part when alg = \"none\".");
                    }
                    alg
                },
                Some(alg) => {
                    if parts.len() != 3 {
                        bail!("JWT must have signature part when alg != \"none\".");
                    }
                    alg
                },
                None => {
                    bail!("JWT alg header claim is required.");
                }
            };

            let verifier = verifier_selector(&jwt);

            let algorithm_alg = verifier.algorithm().name();
            if alg != algorithm_alg {
                bail!(
                    "JWT alg header parameter is mismatched: expected = {}, actual = {}",
                    algorithm_alg,
                    alg
                );
            }

            let signature_base64 = parts.get(2).unwrap();
            let signature = base64::decode_config(signature_base64, base64::URL_SAFE_NO_PAD)?;

            Ok(verifier
                .verify(
                    &[header_base64.as_bytes(), b".", payload_base64.as_bytes()],
                    &signature,
                )
                .map(|_| jwt))
        })()
        .map_err(|err| JwtError::InvalidJwtFormat(err))?
    }

    /// Set a value for token type header claim (typ).
    ///
    /// # Arguments
    /// * `token_type` - A token type (e.g. "JWT")
    pub fn set_token_type(&mut self, token_type: &str) -> &mut Self {
        self.header.insert("typ".to_string(), json!(token_type));
        self
    }

    /// Return a value for token type header claim (typ).
    pub fn token_type(&self) -> Option<&str> {
        match self.header.get("typ") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Return a value for algorithm header claim (alg).
    pub fn algorithm(&self) -> Option<&str> {
        match self.header.get("alg") {
            Some(Value::String(val)) => Some(val),
            _ => None,
        }
    }

    /// Set a value for content type header claim (cty).
    ///
    /// # Arguments
    /// * `content_type` - A content type (e.g. "JWT")
    pub fn set_content_type(&mut self, content_type: &str) -> &mut Self {
        self.header.insert("cty".to_string(), json!(content_type));
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
    pub fn set_key_id(&mut self, key_id: &str) -> &mut Self {
        self.header.insert("kid".to_string(), json!(key_id));
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
    pub fn set_header_claim(&mut self, key: &str, value: &Value) -> &mut Self {
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
    pub fn unset_header_claim(&mut self, key: &str) -> &mut Self{
        self.header.remove(key);
        self
    }

    /// Set a value for a issuer payload claim (iss).
    ///
    /// # Arguments
    /// * `issuer` - A issuer
    pub fn set_issuer(&mut self, issuer: &str) -> &mut Self {
        self.payload.insert("iss".to_string(), json!(issuer));
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
    pub fn set_subject<'a>(&mut self, subject: &str) -> &mut Self {
        self.payload.insert("sub".to_string(), json!(subject));
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
    /// * `audience` - A audience
    pub fn set_audience<'a>(&mut self, audience: &str) -> &mut Self {
        self.payload.insert("aud".to_string(), json!(audience));
        self
    }

    /// Add a value for a audience payload claim (aud).
    ///
    /// # Arguments
    /// * `audience` - A audience
    pub fn add_audience<'a>(&mut self, audience: &str) -> &mut Self {
        match self.payload.entry("aud") {
            Entry::Vacant(entry) => {
                entry.insert(json!(audience));
            }
            Entry::Occupied(mut entry) => match entry.get_mut() {
                Value::Array(vals) => {
                    vals.push(json!(audience));
                }
                Value::String(val) => {
                    let mut vals = Vec::new();
                    vals.push(json!(val));
                    entry.insert(json!(vals));
                }
                _ => {
                    entry.insert(json!(audience));
                }
            },
        }
        self
    }

    /// Set values for a audience payload claim (aud).
    ///
    /// # Arguments
    /// * `audiences` - A list of audiences
    pub fn set_audiences(&mut self, audiences: Vec<&str>) -> &mut Self {
        match self.payload.entry("aud") {
            Entry::Vacant(entry) => {
                let mut list = Vec::new();
                for audience in audiences {
                    list.push(json!(audience));
                }
                entry.insert(json!(list));
            }
            Entry::Occupied(mut entry) => match entry.get_mut() {
                Value::Array(vals) => {
                    for audience in audiences {
                        vals.push(json!(audience.to_string()));
                    }
                }
                Value::String(val) => {
                    let mut vals = Vec::new();
                    vals.push(json!(val.to_string()));
                    for audience in audiences {
                        vals.push(json!(audience.to_string()));
                    }
                    entry.insert(json!(vals));
                }
                _ => {
                    let mut list = Vec::new();
                    for audience in audiences {
                        list.push(json!(audience.to_string()));
                    }
                    entry.insert(json!(list));
                }
            },
        }
        self
    }

    /// Return a value for a audience payload claim (sub).
    pub fn audience(&self) -> Option<Vec<&str>> {
        match self.payload.get("aud") {
            Some(Value::String(str_val)) => {
                let mut list = Vec::new();
                list.push(str_val.as_str());
                Some(list)
            }
            Some(Value::Array(vals)) => {
                let mut list = Vec::new();
                for val in vals {
                    if let Value::String(str_val) = val {
                        list.push(str_val.as_str());
                    }
                }
                Some(list)
            }
            _ => None,
        }
    }

    /// Set a system time for a expires at payload claim (exp).
    ///
    /// # Arguments
    /// * `expires_at` - The expiration time on or after which the JWT must not be accepted for processing.
    pub fn set_expires_at(&mut self, expires_at: &SystemTime) -> &mut Self {
        self.payload.insert(
            "exp".to_string(),
            json!(expires_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()),
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
    pub fn set_not_before(&mut self, not_before: &SystemTime) -> &mut Self {
        self.payload.insert(
            "nbf".to_string(),
            json!(not_before
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()),
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
    pub fn set_issued_at(&mut self, issued_at: &SystemTime) -> &mut Self {
        self.payload.insert(
            "iat".to_string(),
            json!(issued_at
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()),
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
    pub fn set_jwt_id(&mut self, jwt_id: &str) -> &mut Self {
        self.payload.insert("jti".to_string(), json!(jwt_id));
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
    pub fn set_payload_claim(&mut self, key: &str, value: &Value) -> &mut Self {
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
    pub fn unset_payload_claim(&mut self, key: &str) -> &mut Self {
        self.payload.remove(key);
        self
    }

    /// Return a JWT text that is decoded with a "none" algorithm.
    pub fn encode_with_none(&self) -> Result<String, JwtError> {
        let alg_key = "alg".to_string();
        let mut new_header;
        let header = match &self.header.get(&alg_key) {
            Some(Value::String(alg)) if alg == "none" => &self.header,
            _ => {
                new_header = self.header.clone();
                new_header.insert("alg".to_string(), json!("none"));
                &new_header
            }
        };

        let header_json = serde_json::to_string(header).unwrap();
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

/// Represents JWT validator.
#[derive(Debug, Eq, PartialEq)]
pub struct JwtValidator {
    current_time: Option<SystemTime>,
    audience: Vec<String>,
    issuer: Option<String>,
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
        let mut to_jwt = Jwt::decode_with_none(&jwt_string)?;
        to_jwt.unset_header_claim("alg");

        assert_eq!(from_jwt, to_jwt);

        Ok(())
    }

    #[test]
    fn test_jwt_with_hmac() -> Result<()> {
        let from_jwt = Jwt::new();

        for alg in &[HS256, HS384, HS512] {
            let private_key = b"quety12389";
            let signer = alg.signer_from_slice(private_key)?;
            let jwt_string = from_jwt.encode_with_signer(&signer)?;

            let mut to_jwt = Jwt::decode_with_verifier(&jwt_string, &signer)?;
            to_jwt.unset_header_claim("alg");

            assert_eq!(from_jwt, to_jwt);
        }

        Ok(())
    }

    #[test]
    fn test_jwt_with_rsa_pem() -> Result<()> {
        let from_jwt = Jwt::new();

        for alg in &[RS256, RS384, RS512] {
            let private_key = load_file("keys/rsa_2048_private.pem")?;
            let signer = alg.signer_from_pem(&private_key)?;
            let jwt_string = from_jwt.encode_with_signer(&signer)?;

            let public_key = load_file("keys/rsa_2048_public.pem")?;
            let verifier = alg.verifier_from_pem(&public_key)?;
            let mut to_jwt = Jwt::decode_with_verifier(&jwt_string, &verifier)?;
            to_jwt.unset_header_claim("alg");

            assert_eq!(from_jwt, to_jwt);
        }

        Ok(())
    }

    #[test]
    fn test_jwt_with_rsa_der() -> Result<()> {
        let from_jwt = Jwt::new();

        for alg in &[RS256, RS384, RS512] {
            let private_key = load_file("keys/rsa_2048_private.der")?;
            let signer = alg.signer_from_der(&private_key)?;
            let jwt_string = from_jwt.encode_with_signer(&signer)?;

            let public_key = load_file("keys/rsa_2048_public.der")?;
            let verifier = alg.verifier_from_der(&public_key)?;
            let mut to_jwt = Jwt::decode_with_verifier(&jwt_string, &verifier)?;
            to_jwt.unset_header_claim("alg");

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

            let signer = alg.signer_from_pem(&private_key)?;
            let jwt_string = from_jwt.encode_with_signer(&signer)?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            let mut to_jwt = Jwt::decode_with_verifier(&jwt_string, &verifier)?;
            to_jwt.unset_header_claim("alg");

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

            let signer = alg.signer_from_der(&private_key)?;
            let jwt_string = from_jwt.encode_with_signer(&signer)?;

            let verifier = alg.verifier_from_der(&public_key)?;
            let mut to_jwt = Jwt::decode_with_verifier(&jwt_string, &verifier)?;
            to_jwt.unset_header_claim("alg");

            assert_eq!(from_jwt, to_jwt);
        }

        Ok(())
    }

    fn curve_name(name: &str) -> &'static str {
        match name {
            "ES256" => "p256",
            "ES384" => "p384",
            "ES512" => "p521",
            _ => unreachable!(),
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

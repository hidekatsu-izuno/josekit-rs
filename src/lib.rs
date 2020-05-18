pub mod error;
pub mod algorithm;

use std::time::{ SystemTime, Duration };

use anyhow::{ bail };
use serde_json::{ Map };

use crate::algorithm::{ Signer, Verifier, Algorithm, HashAlgorithm };
use crate::algorithm::hmac::HmacAlgorithm;
use crate::algorithm::rsa::RsaAlgorithm;
use crate::algorithm::ecdsa::EcdsaAlgorithm;
use crate::error::JwtError;

/// HMAC with SHA-256
pub const HS256: HmacAlgorithm = HmacAlgorithm::new(HashAlgorithm::SHA256);

/// HMAC with SHA-384
pub const HS384: HmacAlgorithm = HmacAlgorithm::new(HashAlgorithm::SHA384);

/// HMAC with SHA-512
pub const HS512: HmacAlgorithm = HmacAlgorithm::new(HashAlgorithm::SHA512);

/// RSASSA-PKCS1-v1_5 with SHA-256
pub const RS256: RsaAlgorithm = RsaAlgorithm::new(HashAlgorithm::SHA256);

/// RSASSA-PKCS1-v1_5 with SHA-384
pub const RS384: RsaAlgorithm = RsaAlgorithm::new(HashAlgorithm::SHA384);

/// RSASSA-PKCS1-v1_5 with SHA-512
pub const RS512: RsaAlgorithm = RsaAlgorithm::new(HashAlgorithm::SHA512);

/// ECDSA with curve P-256 and SHA-256
pub const ES256: EcdsaAlgorithm = EcdsaAlgorithm::new(HashAlgorithm::SHA256);

/// ECDSA with curve P-384 and SHA-384
pub const ES384: EcdsaAlgorithm = EcdsaAlgorithm::new(HashAlgorithm::SHA384);

/// ECDSA with curve P-521 and SHA-512
pub const ES512: EcdsaAlgorithm = EcdsaAlgorithm::new(HashAlgorithm::SHA512);

pub type Value = serde_json::Value;

#[derive(Debug, Eq, PartialEq)]
pub struct Jwt {
    header: Map<String, Value>,
    payload: Map<String, Value>
}

impl Jwt {
    pub fn new() -> Self {
        let mut header = Map::default();
        header.insert("typ".to_string(), Value::String("JWT".to_string()));

        Self {
            header,
            payload: Map::default()
        }
    }

    pub fn decode_with_none(input: &str) -> Result<Self, JwtError> {
        (|| -> anyhow::Result<Self> {
            let parts: Vec<&str> = input.split('.').collect();
            if parts.len() != 2 {
                bail!("JWT must be two parts separated by colon.");
            }

            let header_base64 = parts.get(0).unwrap();
            let payload_base64 = parts.get(1).unwrap();
            
            let header_json = base64::decode_config(header_base64, base64::URL_SAFE_NO_PAD)?;
            let mut header: Map<String, Value> = serde_json::from_slice(&header_json)?;

            let payload_json = base64::decode_config(payload_base64, base64::URL_SAFE_NO_PAD)?;
            let payload: Map<String, Value> = serde_json::from_slice(&payload_json)?;

            if let Some(Value::String(expected_alg)) = header.remove("alg") {
                let actual_alg = "none".to_string();
                if expected_alg != actual_alg {
                    bail!("JWT alg header parameter is mismatched: expected = {}, actual = {}", &expected_alg, &actual_alg);
                }
            } else {
                bail!("JWT alg header parameter is missing.");
            }

            Ok(Jwt {
                header,
                payload
            })
        })().map_err(|err| {
            JwtError::InvalidJwtFormat(err)
        })
    }

    pub fn decode_with_verify<T: Algorithm>(input: &str, verifier: &impl Verifier<T>) -> Result<Self, JwtError> {
        let (
            header,
            payload,
            data,
            signature
        ) = (|| -> anyhow::Result<(Map<String, Value>, Map<String, Value>, [&[u8]; 3], Vec<u8>)> {
            let parts: Vec<&str> = input.split('.').collect();
            if parts.len() != 3 {
                bail!("JWT must be three parts separated by colon.");
            }
    
            let header_base64 = parts.get(0).unwrap();
            let payload_base64 = parts.get(1).unwrap();
            let signature_base64 = parts.get(2).unwrap();
            
            let header_json = base64::decode_config(header_base64, base64::URL_SAFE_NO_PAD)?;
            let mut header: Map<String, Value> = serde_json::from_slice(&header_json)?;

            let payload_json = base64::decode_config(payload_base64, base64::URL_SAFE_NO_PAD)?;
            let payload: Map<String, Value> = serde_json::from_slice(&payload_json)?;

            if let Some(Value::String(expected_alg)) = header.remove("alg") {
                let actual_alg = verifier.algorithm().name();
                if expected_alg != actual_alg {
                    bail!("JWT alg header parameter is mismatched: expected = {}, actual = {}", &expected_alg, &actual_alg);
                }
            } else {
                bail!("JWT alg header parameter is missing.");
            }
    
            let signature = base64::decode_config(signature_base64, base64::URL_SAFE_NO_PAD)?;

            Ok((
                header,
                payload,
                [header_base64.as_bytes(), b".", payload_base64.as_bytes()],
                signature
            ))
        })().map_err(|err| {
            JwtError::InvalidJwtFormat(err)
        })?;
        
        verifier.verify(&data, &signature)?;

        Ok(Jwt {
            header,
            payload
        })
    }

    pub fn set_token_type(mut self, token_type: &str) -> Self {
        self.header.insert("typ".to_string(), Value::String(token_type.to_string()));
        self
    }

    pub fn token_type(&self) -> Option<&str> {
        match self.header.get("typ") {
            Some(Value::String(val)) => Some(val),
            _ => None
        }
    }

    pub fn algorithm(&self) -> Option<&str> {
        match self.header.get("alg") {
            Some(Value::String(val)) => Some(val),
            _ => None
        }
    }

    pub fn set_content_type(mut self, content_type: &str) -> Self {
        self.header.insert("cty".to_string(), Value::String(content_type.to_string()));
        self
    }
    
    pub fn content_type(&self) -> Option<&str> {
        match self.header.get("cty") {
            Some(Value::String(val)) => Some(val),
            _ => None
        }
    }

    pub fn set_key_id(mut self, key_id: &str) -> Self {
        self.header.insert("kid".to_string(), Value::String(key_id.to_string()));
        self
    }
    
    pub fn key_id(&self) -> Option<&str> {
        match self.header.get("kid") {
            Some(Value::String(val)) => Some(val),
            _ => None
        }
    }

    pub fn set_header_claim(mut self, key: &str, value: &Value) -> Self {
        self.header.insert(key.to_string(), (*value).clone());
        self
    }

    pub fn header_claim(&self, key: &str) -> Option<&Value> {
        self.header.get(key)
    }

    pub fn unset_header_claim(mut self, key: &str) -> Self {
        self.header.remove(key);
        self
    }

    pub fn set_issuer(mut self, issuer: &str) -> Self {
        self.payload.insert("iss".to_string(), Value::String(issuer.to_string()));
        self
    }

    pub fn issuer(&self) -> Option<&str> {
        match self.payload.get("iss") {
            Some(Value::String(val)) => Some(val),
            _ => None
        }
    }

    pub fn set_subject<'a>(mut self, subject: &str) -> Self {
        self.payload.insert("sub".to_string(), Value::String(subject.to_string()));
        self
    }

    pub fn subject(&self) -> Option<&str> {
        match self.payload.get("sub") {
            Some(Value::String(val)) => Some(val),
            _ => None
        }
    }

    pub fn set_audience(mut self, audience: &str) -> Self {
        self.payload.insert("aud".to_string(), Value::String(audience.to_string()));
        self
    }
    
    pub fn audience(&self) -> Option<&str> {
        match self.payload.get("aud") {
            Some(Value::String(val)) => Some(val),
            _ => None
        }
    }

    pub fn set_expires_at(mut self, expires_at: &SystemTime) -> Self {
        self.payload.insert("exp".to_string(), Value::Number(expires_at
            .duration_since(SystemTime::UNIX_EPOCH).unwrap()
            .as_secs().into()));
        self
    }

    pub fn expires_at(&self) -> Option<SystemTime> {
        match self.payload.get("exp") {
            Some(Value::Number(val)) => match val.as_u64() {
                Some(val) => Some(SystemTime::UNIX_EPOCH + Duration::from_secs(val)),
                _ => None
            },
            _ => None
        }
    }

    pub fn set_not_before(mut self, not_before: &SystemTime) -> Self {
        self.payload.insert("nbf".to_string(), Value::Number(not_before
            .duration_since(SystemTime::UNIX_EPOCH).unwrap()
            .as_secs().into()));
        self
    }

    pub fn not_before(&self) -> Option<SystemTime> {
        match self.payload.get("nbf") {
            Some(Value::Number(val)) => match val.as_u64() {
                Some(val) => Some(SystemTime::UNIX_EPOCH + Duration::from_secs(val)),
                _ => None
            },
            _ => None
        }
    }

    pub fn set_issued_at(mut self, issued_at: &SystemTime) -> Self {
        self.payload.insert("iat".to_string(), Value::Number(issued_at
            .duration_since(SystemTime::UNIX_EPOCH).unwrap()
            .as_secs().into()));
        self
    }

    pub fn issued_at(&self) -> Option<SystemTime> {
        match self.payload.get("iat") {
            Some(Value::Number(val)) => match val.as_u64() {
                Some(val) => Some(SystemTime::UNIX_EPOCH + Duration::from_secs(val)),
                _ => None
            },
            _ => None
        }
    }

    pub fn set_jwt_id(mut self, jwt_id: &str) -> Self {
        self.payload.insert("jti".to_string(), Value::String(jwt_id.to_string()));
        self
    }

    pub fn jwt_id(&self) -> Option<&str> {
        match self.payload.get("jti") {
            Some(Value::String(val)) => Some(val),
            _ => None
        }
    }

    pub fn set_payload_claim(mut self, key: &str, value: &Value) -> Self {
        self.payload.insert(key.to_string(), (*value).clone());
        self
    }
    
    pub fn payload_claim(&self, key: &str) -> Option<&Value> {
        self.payload.get(key)
    }

    pub fn unset_payload_claim(mut self, key: &str) -> Self {
        self.payload.remove(key);
        self
    }

    pub fn encode_with_none(&self) -> Result<String, JwtError> {
        let mut header = self.header.clone();
        header.insert("alg".to_string(), Value::String("none".to_string()));

        let header_json = serde_json::to_string(&header).unwrap();
        let header_base64 = base64::encode_config(header_json, base64::URL_SAFE_NO_PAD);

        let payload_json = serde_json::to_string(&self.payload).unwrap();
        let payload_base64 = base64::encode_config(payload_json, base64::URL_SAFE_NO_PAD);

        Ok(format!("{}.{}", header_base64, payload_base64))
    }

    pub fn encode_with_sign<T: Algorithm>(&self, signer: &impl Signer<T>) -> Result<String, JwtError> {
        let name = signer.algorithm().name();

        let mut header = self.header.clone();
        header.insert("alg".to_string(), Value::String(name.to_string()));

        let header_json = serde_json::to_string(&header).unwrap();
        let header_base64 = base64::encode_config(header_json, base64::URL_SAFE_NO_PAD);

        let payload_json = serde_json::to_string(&self.payload).unwrap();
        let payload_base64 = base64::encode_config(payload_json, base64::URL_SAFE_NO_PAD);

        let signature = signer.sign(&[header_base64.as_bytes(), b".", payload_base64.as_bytes()])?;

        let signature_base64 = base64::encode_config(signature, base64::URL_SAFE_NO_PAD);
        Ok(format!("{}.{}.{}", header_base64, payload_base64, signature_base64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;
    use anyhow::Result;

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

        for alg in &[ HS256, HS384, HS512 ] {
            let private_key = b"quety12389";
            let signer = alg.signer_from_bytes(private_key)?;
            let jwt_string = from_jwt.encode_with_sign(&signer)?;
    
            let to_jwt = Jwt::decode_with_verify(&jwt_string, &signer)?;

            assert_eq!(from_jwt, to_jwt);
        }

        Ok(())
    }

    #[test]
    fn test_jwt_with_rsa_pem() -> Result<()> {
        let from_jwt = Jwt::new();

        for alg in &[ RS256, RS384, RS512 ] {
            let private_key = load_file("keys/rsa_2048_private.pem")?;
            let signer = alg.signer_from_private_pem(&private_key)?;
            let jwt_string = from_jwt.encode_with_sign(&signer)?;
    
            let public_key = load_file("keys/rsa_2048_public.pem")?;
            let verifier = alg.verifier_from_public_pem(&public_key)?;
            let to_jwt = Jwt::decode_with_verify(&jwt_string, &verifier)?;

            assert_eq!(from_jwt, to_jwt);
        }

        Ok(())
    }

    #[test]
    fn test_jwt_with_rsa_der() -> Result<()> {
        let from_jwt = Jwt::new();

        for alg in &[ RS256, RS384, RS512 ] {
            let private_key = load_file("keys/rsa_2048_private.der")?;
            let signer = alg.signer_from_private_der(&private_key)?;
            let jwt_string = from_jwt.encode_with_sign(&signer)?;
    
            let public_key = load_file("keys/rsa_2048_public.der")?;
            let verifier = alg.verifier_from_public_der(&public_key)?;
            let to_jwt = Jwt::decode_with_verify(&jwt_string, &verifier)?;

            assert_eq!(from_jwt, to_jwt);
        }

        Ok(())
    }

    #[test]
    fn test_jwt_with_ecdsa_pem() -> Result<()> {
        let from_jwt = Jwt::new();

        for alg in &[ ES256, ES384, ES512 ] {
            let private_key = load_file("keys/ecdsa_p256_private.pem")?;
            let signer = alg.signer_from_private_pem(&private_key)?;
            let jwt_string = from_jwt.encode_with_sign(&signer)?;
    
            let public_key = load_file("keys/ecdsa_p256_public.pem")?;
            let verifier = alg.verifier_from_public_pem(&public_key)?;
            let to_jwt = Jwt::decode_with_verify(&jwt_string, &verifier)?;

            assert_eq!(from_jwt, to_jwt);
        }

        Ok(())
    }

    #[test]
    fn test_jwt_with_ecdsa_der() -> Result<()> {
        let from_jwt = Jwt::new();

        for alg in &[ ES256, ES384, ES512 ] {
            let private_key = load_file("keys/ecdsa_p256_private.der")?;
            let signer = alg.signer_from_private_der(&private_key)?;
            let jwt_string = from_jwt.encode_with_sign(&signer)?;
    
            let public_key = load_file("keys/ecdsa_p256_public.der")?;
            let verifier = alg.verifier_from_public_der(&public_key)?;
            let to_jwt = Jwt::decode_with_verify(&jwt_string, &verifier)?;

            assert_eq!(from_jwt, to_jwt);
        }

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
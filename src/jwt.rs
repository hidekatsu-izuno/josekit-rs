use anyhow::{ Result, bail, anyhow };

use std::collections::BTreeMap;
use std::time::{ SystemTime, Duration };

use crate::algorithm::{ Signer, Verifier, HashAlgorithm };
use crate::algorithm::hmac::HmacAlgorithm;
use crate::algorithm::rsa::RsaAlgorithm;
use crate::algorithm::ecdsa::EcdsaAlgorithm;
use crate::error::JwtError;

pub const HS256: HmacAlgorithm = HmacAlgorithm::new(HashAlgorithm::SHA256);
pub const HS384: HmacAlgorithm = HmacAlgorithm::new(HashAlgorithm::SHA384);
pub const HS512: HmacAlgorithm = HmacAlgorithm::new(HashAlgorithm::SHA512);
pub const RS256: RsaAlgorithm = RsaAlgorithm::new(HashAlgorithm::SHA256);
pub const RS384: RsaAlgorithm = RsaAlgorithm::new(HashAlgorithm::SHA384);
pub const RS512: RsaAlgorithm = RsaAlgorithm::new(HashAlgorithm::SHA512);
pub const ES256: EcdsaAlgorithm = EcdsaAlgorithm::new(HashAlgorithm::SHA256);
pub const ES384: EcdsaAlgorithm = EcdsaAlgorithm::new(HashAlgorithm::SHA384);
pub const ES512: EcdsaAlgorithm = EcdsaAlgorithm::new(HashAlgorithm::SHA512);

pub type Value = serde_json::Value;

#[derive(Debug, Eq, PartialEq, Default)]
pub struct Jwt {
    header: BTreeMap<String, Value>,
    payload: BTreeMap<String, Value>
}

impl Jwt {
    pub fn decode(input: &str, verifier: &dyn Verifier) -> Result<Jwt> {
        let parts: Vec<&str> = input.split('.').collect();
        if parts.len() != 3 {
            bail!(JwtError::InvalidJwtFormat);
        }

        let header_base64 = parts.get(0).unwrap();
        let payload_base64 = parts.get(1).unwrap();
        let signature_base64 = parts.get(2).unwrap();

        let signature = base64::decode_config(signature_base64, base64::URL_SAFE_NO_PAD)?;
        verifier.verify(format!("{}.{}", header_base64, payload_base64).as_bytes(), &signature)?;

        let header_json = base64::decode_config(header_base64, base64::URL_SAFE_NO_PAD)?;
        let payload_json = base64::decode_config(payload_base64, base64::URL_SAFE_NO_PAD)?;

        let header: BTreeMap<String, Value> = serde_json::from_slice(&header_json)?;
        let payload: BTreeMap<String, Value> = serde_json::from_slice(&payload_json)?;

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

    pub fn remove_header_claim(mut self, key: &str) -> Self {
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

    pub fn remove_payload_claim(mut self, key: &str) -> Self {
        self.payload.remove(key);
        self
    }

    pub fn encode(&self, signer: &impl Signer) -> Result<String> {
        let header_json = serde_json::to_string(&self.header).map_err(|err| {
            JwtError::InvalidJsonFormat(anyhow!(err))
        })?;

        let payload_json = serde_json::to_string(&self.payload).map_err(|err| {
            JwtError::InvalidJsonFormat(anyhow!(err))
        })?;

        let header_base64 = base64::encode_config(header_json, base64::URL_SAFE_NO_PAD);
        let payload_base64 = base64::encode_config(payload_json, base64::URL_SAFE_NO_PAD);

        let signature = signer.sign(format!("{}.{}", header_base64, payload_base64).as_bytes())?;
        let signature_base64 = base64::encode_config(signature, base64::URL_SAFE_NO_PAD);

        Ok(format!("{}.{}.{}", header_base64, payload_base64, signature_base64))
    }
}

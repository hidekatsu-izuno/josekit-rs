use anyhow::bail;
use once_cell::sync::Lazy;
use openssl::pkey::{HasPublic, PKey, Private, Public};
use openssl::rsa::Padding;
use serde_json::Value;

use crate::der::oid::ObjectIdentifier;
use crate::der::{DerBuilder, DerReader, DerType, DerClass};
use crate::jose::JoseError;
use crate::jwe::{JweAlgorithm, JweDecrypter, JweEncrypter};
use crate::jwk::Jwk;

static OID_RSA_ENCRYPTION: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 1]));

static OID_RSAES_OAEP: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 7]));

static OID_P_SPECIFIED: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 9]));

static OID_SHA1: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 3, 14, 3, 2, 26]));

static OID_SHA256: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 16, 840, 1, 101, 3, 4, 2, 1]));

static OID_SHA384: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 16, 840, 1, 101, 3, 4, 2, 2]));

static OID_SHA512: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 16, 840, 1, 101, 3, 4, 2, 3]));

static OID_MGF1: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 8]));

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum RsaesJweAlgorithm {
    /// RSAES-PKCS1-v1_5
    #[deprecated(note = "This algorithm is no longer recommended.")]
    Rsa1_5,
    /// RSAES OAEP using default parameters
    RsaOaep,
    /// RSAES OAEP using SHA-256 and MGF1 with SHA-256
    RsaOaep256,
    /// RSAES OAEP using SHA-384 and MGF1 with SHA-384
    RsaOaep384,
    /// RSAES OAEP using SHA-512 and MGF1 with SHA-512
    RsaOaep512,
}

impl RsaesJweAlgorithm {
    pub fn encrypter_from_jwk(&self, jwk: &Jwk) -> Result<RsaesJweEncrypter, JoseError> {
        (|| -> anyhow::Result<RsaesJweEncrypter> {
            match jwk.key_type() {
                val if val == self.key_type() => {}
                val => bail!("A parameter kty must be {}: {}", self.key_type(), val),
            }
            match jwk.key_use() {
                Some(val) if val == "enc" => {}
                None => {}
                Some(val) => bail!("A parameter use must be enc: {}", val),
            }
            match jwk.key_operations() {
                Some(vals) => {
                    if !vals.iter().any(|e| e == "encrypt")
                        || !vals.iter().any(|e| e == "wrapKey") {
                        bail!("A parameter key_ops must contains encrypt and wrapKey.");
                    }
                },
                None => {},
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }

            let n = match jwk.parameter("n") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter n must be a string."),
                None => bail!("A parameter n is required."),
            };
            let e = match jwk.parameter("e") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter e must be a string."),
                None => bail!("A parameter e is required."),
            };

            let mut builder = DerBuilder::new();
            builder.begin(DerType::Sequence);
            {
                builder.append_integer_from_be_slice(&n, false); // n
                builder.append_integer_from_be_slice(&e, false); // e
            }
            builder.end();

            let pkcs8 = self.to_pkcs8(&builder.build(), true);
            let public_key = PKey::public_key_from_der(&pkcs8)?;
            let key_id = jwk.key_id().map(|val| val.to_string());

            self.check_key(&public_key)?;

            Ok(RsaesJweEncrypter {
                algorithm: self.clone(),
                public_key,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn decrypter_from_jwk(&self, jwk: &Jwk) -> Result<RsaesJweDecrypter, JoseError> {
        (|| -> anyhow::Result<RsaesJweDecrypter> {
            match jwk.key_type() {
                val if val == self.key_type() => {}
                val => bail!("A parameter kty must be {}: {}", self.key_type(), val),
            }
            match jwk.key_use() {
                Some(val) if val == "sig" => {}
                None => {}
                Some(val) => bail!("A parameter use must be sig: {}", val),
            }
            match jwk.key_operations() {
                Some(vals) => {
                    if !vals.iter().any(|e| e == "decrypt")
                        || !vals.iter().any(|e| e == "unwrapKey") {
                        bail!("A parameter key_ops must contains decrypt and unwrapKey.");
                    }
                },
                None => {},
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }
            let n = match jwk.parameter("n") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter n must be a string."),
                None => bail!("A parameter n is required."),
            };
            let e = match jwk.parameter("e") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter e must be a string."),
                None => bail!("A parameter e is required."),
            };
            let d = match jwk.parameter("d") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter d must be a string."),
                None => bail!("A parameter d is required."),
            };
            let p = match jwk.parameter("p") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter p must be a string."),
                None => bail!("A parameter p is required."),
            };
            let q = match jwk.parameter("q") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter q must be a string."),
                None => bail!("A parameter q is required."),
            };
            let dp = match jwk.parameter("dp") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter dp must be a string."),
                None => bail!("A parameter dp is required."),
            };
            let dq = match jwk.parameter("dq") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter dq must be a string."),
                None => bail!("A parameter dq is required."),
            };
            let qi = match jwk.parameter("qi") {
                Some(Value::String(val)) => base64::decode_config(val, base64::URL_SAFE_NO_PAD)?,
                Some(_) => bail!("A parameter qi must be a string."),
                None => bail!("A parameter qi is required."),
            };

            let mut builder = DerBuilder::new();
            builder.begin(DerType::Sequence);
            {
                builder.append_integer_from_u8(0); // version
                builder.append_integer_from_be_slice(&n, false); // n
                builder.append_integer_from_be_slice(&e, false); // e
                builder.append_integer_from_be_slice(&d, false); // d
                builder.append_integer_from_be_slice(&p, false); // p
                builder.append_integer_from_be_slice(&q, false); // q
                builder.append_integer_from_be_slice(&dp, false); // d mod (p-1)
                builder.append_integer_from_be_slice(&dq, false); // d mod (q-1)
                builder.append_integer_from_be_slice(&qi, false); // (inverse of q) mod p
            }
            builder.end();

            let pkcs8 = self.to_pkcs8(&builder.build(), false);
            let private_key = PKey::private_key_from_der(&pkcs8)?;
            let key_id = jwk.key_id().map(|val| val.to_string());

            self.check_key(&private_key)?;

            Ok(RsaesJweDecrypter {
                algorithm: self.clone(),
                private_key,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn check_key<T: HasPublic>(&self, pkey: &PKey<T>) -> anyhow::Result<()> {
        let rsa = pkey.rsa()?;

        if rsa.size() * 8 < 2048 {
            bail!("key length must be 2048 or more.");
        }

        Ok(())
    }

    #[allow(deprecated)]
    fn to_pkcs8(&self, input: &[u8], is_public: bool) -> Vec<u8> {
        let mut builder = DerBuilder::new();
        builder.begin(DerType::Sequence);
        {
            if !is_public {
                builder.append_integer_from_u8(0);
            }

            builder.begin(DerType::Sequence);
            if let Self::Rsa1_5 = self {
                builder.append_object_identifier(&OID_RSA_ENCRYPTION);
                builder.append_null();
            } else {
                builder.append_object_identifier(&OID_RSAES_OAEP);
                builder.begin(DerType::Sequence);
                {
                    builder.begin(DerType::Other(DerClass::ContextSpecific, 0));
                    {
                        builder.begin(DerType::Sequence);
                        {
                            builder.append_object_identifier(self.hash_oid());
                        }
                        builder.end();
                    }
                    builder.end();

                    builder.begin(DerType::Other(DerClass::ContextSpecific, 1));
                    {
                        builder.begin(DerType::Sequence);
                        {
                            builder.append_object_identifier(&OID_MGF1);
                            builder.begin(DerType::Sequence);
                            {
                                builder.append_object_identifier(self.hash_oid());
                            }
                            builder.end();
                        }
                        builder.end();
                    }
                    builder.end();

                    builder.begin(DerType::Other(DerClass::ContextSpecific, 2));
                    {
                        builder.append_object_identifier(&OID_P_SPECIFIED);
                    }
                    builder.end();
                }
                builder.end();
            }
            builder.end();

            if is_public {
                builder.append_bit_string_from_slice(input, 0);
            } else {
                builder.append_octed_string_from_slice(input);
            }
        }
        builder.end();

        builder.build()
    }

    #[allow(deprecated)]
    fn padding(&self) -> Padding {
        match self {
            Self::Rsa1_5 => Padding::PKCS1,
            Self::RsaOaep => Padding::PKCS1_OAEP,
            Self::RsaOaep256 => Padding::PKCS1_OAEP,
            Self::RsaOaep384 => Padding::PKCS1_OAEP,
            Self::RsaOaep512 => Padding::PKCS1_OAEP,
        }
    }
    
    fn hash_oid(&self) -> &ObjectIdentifier {
        match self {
            Self::RsaOaep => &OID_SHA1,
            Self::RsaOaep256 => &OID_SHA256,
            Self::RsaOaep384 => &OID_SHA384,
            Self::RsaOaep512 => &OID_SHA512,
            _ => unreachable!(),
        }
    }
}

impl JweAlgorithm for RsaesJweAlgorithm {
    #[allow(deprecated)]
    fn name(&self) -> &str {
        match self {
            Self::Rsa1_5 => "RSA1_5",
            Self::RsaOaep => "RSA-OAEP",
            Self::RsaOaep256 => "RSA-OAEP-256",
            Self::RsaOaep384 => "RSA-OAEP-384",
            Self::RsaOaep512 => "RSA-OAEP-512",
        }
    }

    fn key_type(&self) -> &str {
        "RSA"
    }
}

#[derive(Debug, Clone)]
pub struct RsaesJweEncrypter {
    algorithm: RsaesJweAlgorithm,
    public_key: PKey<Public>,
    key_id: Option<String>,
}

impl JweEncrypter for RsaesJweEncrypter {
    fn algorithm(&self) -> &dyn JweAlgorithm {
        &self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn set_key_id(&mut self, key_id: &str) {
        self.key_id = Some(key_id.to_string());
    }

    fn remove_key_id(&mut self) {
        self.key_id = None;
    }

    fn direct_content_encryption_key(&self) -> Option<&[u8]> {
        None
    }

    fn encrypt(&self, message: &[u8]) -> Result<Vec<u8>, JoseError> {
        let rsa = self.public_key.rsa().unwrap();
        let padding = self.algorithm.padding();

        (|| -> anyhow::Result<Vec<u8>> {
            let mut encrypted_message = Vec::new();
            let _len = rsa.public_encrypt(message, &mut encrypted_message, padding)?;
            Ok(encrypted_message)
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }
}

#[derive(Debug, Clone)]
pub struct RsaesJweDecrypter {
    algorithm: RsaesJweAlgorithm,
    private_key: PKey<Private>,
    key_id: Option<String>,
}

impl JweDecrypter for RsaesJweDecrypter {
    fn algorithm(&self) -> &dyn JweAlgorithm {
        &self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    fn set_key_id(&mut self, key_id: &str) {
        self.key_id = Some(key_id.to_string());
    }

    fn remove_key_id(&mut self) {
        self.key_id = None;
    }

    fn direct_content_encryption_key(&self) -> Option<&[u8]> {
        None
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, JoseError> {
        let rsa = self.private_key.rsa().unwrap();
        let padding = self.algorithm.padding();

        (|| -> anyhow::Result<Vec<u8>> {
            let mut message = Vec::new();
            let _len = rsa.private_decrypt(data, &mut message, padding)?;
            Ok(message)
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }
}

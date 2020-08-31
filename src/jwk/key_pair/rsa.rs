use std::ops::Deref;

use anyhow::bail;
use once_cell::sync::Lazy;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use serde_json::Value;

use crate::der::oid::ObjectIdentifier;
use crate::der::{DerBuilder, DerReader, DerType};
use crate::jose::JoseError;
use crate::jwk::{Jwk, KeyPair};

static OID_RSA_ENCRYPTION: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 1]));

#[derive(Debug, Clone)]
pub struct RsaKeyPair {
    private_key: PKey<Private>,
    alg: Option<String>,
}

impl RsaKeyPair {
    pub(crate) fn from_private_key(private_key: PKey<Private>) -> RsaKeyPair {
        RsaKeyPair {
            private_key,
            alg: None,
        }
    }

    pub(crate) fn into_private_key(self) -> PKey<Private> {
        self.private_key
    }

    /// Generate RSA key pair.
    ///
    /// # Arguments
    /// * `bits` - RSA key length
    pub fn generate(bits: u32) -> Result<RsaKeyPair, JoseError> {
        (|| -> anyhow::Result<RsaKeyPair> {
            if bits < 2048 {
                bail!("key length must be 2048 or more.");
            }

            let rsa = Rsa::generate(bits)?;
            let private_key = PKey::from_rsa(rsa)?;

            Ok(RsaKeyPair {
                private_key,
                alg: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn to_raw_private_key(&self) -> Vec<u8> {
        let rsa = self.private_key.rsa().unwrap();
        rsa.private_key_to_der().unwrap()
    }

    pub fn to_traditional_pem_private_key(&self) -> Vec<u8> {
        let rsa = self.private_key.rsa().unwrap();
        rsa.private_key_to_pem().unwrap()
    }

    pub fn to_raw_public_key(&self) -> Vec<u8> {
        let rsa = self.private_key.rsa().unwrap();
        rsa.public_key_to_der_pkcs1().unwrap()
    }

    pub fn to_traditional_pem_public_key(&self) -> Vec<u8> {
        let rsa = self.private_key.rsa().unwrap();
        rsa.public_key_to_pem_pkcs1().unwrap()
    }

    fn to_jwk(&self, private: bool, _public: bool) -> Jwk {
        let rsa = self.private_key.rsa().unwrap();

        let mut jwk = Jwk::new("RSA");
        if let Some(val) = &self.alg {
            jwk.set_algorithm(val);
        }

        let n = rsa.n().to_vec();
        let n = base64::encode_config(n, base64::URL_SAFE_NO_PAD);
        jwk.set_parameter("n", Some(Value::String(n))).unwrap();

        let e = rsa.e().to_vec();
        let e = base64::encode_config(e, base64::URL_SAFE_NO_PAD);
        jwk.set_parameter("e", Some(Value::String(e))).unwrap();

        if private {
            let d = rsa.d().to_vec();
            let d = base64::encode_config(d, base64::URL_SAFE_NO_PAD);
            jwk.set_parameter("d", Some(Value::String(d))).unwrap();

            let p = rsa.p().unwrap().to_vec();
            let p = base64::encode_config(p, base64::URL_SAFE_NO_PAD);
            jwk.set_parameter("p", Some(Value::String(p))).unwrap();

            let q = rsa.q().unwrap().to_vec();
            let q = base64::encode_config(q, base64::URL_SAFE_NO_PAD);
            jwk.set_parameter("q", Some(Value::String(q))).unwrap();

            let dp = rsa.dmp1().unwrap().to_vec();
            let dp = base64::encode_config(dp, base64::URL_SAFE_NO_PAD);
            jwk.set_parameter("dp", Some(Value::String(dp))).unwrap();

            let dq = rsa.dmq1().unwrap().to_vec();
            let dq = base64::encode_config(dq, base64::URL_SAFE_NO_PAD);
            jwk.set_parameter("dq", Some(Value::String(dq))).unwrap();

            let qi = rsa.iqmp().unwrap().to_vec();
            let qi = base64::encode_config(qi, base64::URL_SAFE_NO_PAD);
            jwk.set_parameter("qi", Some(Value::String(qi))).unwrap();
        }

        jwk
    }

    pub(crate) fn detect_pkcs8(input: &[u8], is_public: bool) -> Option<()> {
        let mut reader = DerReader::from_reader(input);

        match reader.next() {
            Ok(Some(DerType::Sequence)) => {}
            _ => return None,
        }

        {
            if !is_public {
                // Version
                match reader.next() {
                    Ok(Some(DerType::Integer)) => match reader.to_u8() {
                        Ok(val) => {
                            if val != 0 {
                                return None;
                            }
                        }
                        _ => return None,
                    },
                    _ => return None,
                }
            }

            match reader.next() {
                Ok(Some(DerType::Sequence)) => {}
                _ => return None,
            }

            {
                match reader.next() {
                    Ok(Some(DerType::ObjectIdentifier)) => match reader.to_object_identifier() {
                        Ok(val) => {
                            if val != *OID_RSA_ENCRYPTION {
                                return None;
                            }
                        }
                        _ => return None,
                    },
                    _ => return None,
                }

                match reader.next() {
                    Ok(Some(DerType::Null)) => {}
                    _ => return None,
                }
            }
        }

        Some(())
    }

    pub(crate) fn to_pkcs8(input: &[u8], is_public: bool) -> Vec<u8> {
        let mut builder = DerBuilder::new();
        builder.begin(DerType::Sequence);
        {
            if !is_public {
                builder.append_integer_from_u8(0);
            }

            builder.begin(DerType::Sequence);
            {
                builder.append_object_identifier(&OID_RSA_ENCRYPTION);
                builder.append_null();
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
}

impl KeyPair for RsaKeyPair {
    fn set_algorithm(&mut self, value: Option<&str>) {
        self.alg = value.map(|val| val.to_string());
    }

    fn algorithm(&self) -> Option<&str> {
        match &self.alg {
            Some(val) => Some(val.as_str()),
            None => None,
        }
    }

    fn to_der_private_key(&self) -> Vec<u8> {
        Self::to_pkcs8(&self.to_raw_private_key(), false)
    }

    fn to_der_public_key(&self) -> Vec<u8> {
        self.private_key.public_key_to_der().unwrap()
    }

    fn to_pem_private_key(&self) -> Vec<u8> {
        self.private_key.private_key_to_pem_pkcs8().unwrap()
    }

    fn to_pem_public_key(&self) -> Vec<u8> {
        self.private_key.public_key_to_pem().unwrap()
    }

    fn to_jwk_private_key(&self) -> Jwk {
        self.to_jwk(true, false)
    }

    fn to_jwk_public_key(&self) -> Jwk {
        self.to_jwk(false, true)
    }

    fn to_jwk_keypair(&self) -> Jwk {
        self.to_jwk(true, true)
    }

    fn box_clone(&self) -> Box<dyn KeyPair> {
        Box::new(self.clone())
    }
}

impl Deref for RsaKeyPair {
    type Target = dyn KeyPair;

    fn deref(&self) -> &Self::Target {
        self
    }
}

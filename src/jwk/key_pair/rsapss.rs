use std::ops::Deref;

use anyhow::bail;
use once_cell::sync::Lazy;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use serde_json::Value;

use crate::der::oid::ObjectIdentifier;
use crate::der::{DerBuilder, DerClass, DerReader, DerType};
use crate::jose::JoseError;
use crate::jwk::{Jwk, KeyPair};
use crate::util::MessageDigest;

static OID_RSASSA_PSS: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 10]));

static OID_SHA256: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 16, 840, 1, 101, 3, 4, 2, 1]));

static OID_SHA384: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 16, 840, 1, 101, 3, 4, 2, 2]));

static OID_SHA512: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 16, 840, 1, 101, 3, 4, 2, 3]));

static OID_MGF1: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 8]));

#[derive(Debug, Clone)]
pub struct RsaPssKeyPair {
    private_key: PKey<Private>,
    md: MessageDigest,
    mgf1_md: MessageDigest,
    salt_len: u8,
    alg: Option<String>,
}

impl RsaPssKeyPair {
    pub(crate) fn from_private_key(
        private_key: PKey<Private>,
        md: MessageDigest,
        mgf1_md: MessageDigest,
        salt_len: u8,
    ) -> RsaPssKeyPair {
        RsaPssKeyPair {
            private_key,
            md,
            mgf1_md,
            salt_len,
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
    pub fn generate(
        bits: u32,
        md: MessageDigest,
        mgf1_md: MessageDigest,
        salt_len: u8,
    ) -> Result<RsaPssKeyPair, JoseError> {
        (|| -> anyhow::Result<RsaPssKeyPair> {
            if bits < 2048 {
                bail!("key length must be 2048 or more.");
            }

            let rsa = Rsa::generate(bits)?;
            let private_key = PKey::from_rsa(rsa)?;

            Ok(RsaPssKeyPair {
                private_key,
                md,
                mgf1_md,
                salt_len,
                alg: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn to_raw_private_key(&self) -> Vec<u8> {
        let rsa = self.private_key.rsa().unwrap();
        rsa.private_key_to_der().unwrap()
    }

    pub fn to_raw_public_key(&self) -> Vec<u8> {
        let rsa = self.private_key.rsa().unwrap();
        rsa.public_key_to_der_pkcs1().unwrap()
    }

    pub fn to_traditional_pem_private_key(&self) -> Vec<u8> {
        let der = self.to_der_private_key();
        let der = base64::encode_config(&der, base64::STANDARD);

        let mut result = String::new();
        result.push_str("-----BEGIN RSA-PSS PRIVATE KEY-----\r\n");
        for i in 0..((der.len() + 64 - 1) / 64) {
            result.push_str(&der[(i * 64)..std::cmp::min((i + 1) * 64, der.len())]);
            result.push_str("\r\n");
        }
        result.push_str("-----END RSA-PSS PRIVATE KEY-----\r\n");
        result.into_bytes()
    }

    fn to_jwk(&self, private: bool, public: bool) -> Jwk {
        let rsa = self.private_key.rsa().unwrap();

        let mut jwk = Jwk::new("RSA");
        jwk.set_key_use("sig");
        jwk.set_key_operations({
            let mut key_ops = Vec::new();
            if private {
                key_ops.push("sign");
            }
            if public {
                key_ops.push("verify");
            }
            key_ops
        });
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

    pub(crate) fn detect_pkcs8(
        input: &[u8],
        is_public: bool,
    ) -> Option<(MessageDigest, MessageDigest, u8)> {
        let md;
        let mgf1_md;
        let salt_len;
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
                            if val != *OID_RSASSA_PSS {
                                return None;
                            }
                        }
                        _ => return None,
                    },
                    _ => return None,
                }

                match reader.next() {
                    Ok(Some(DerType::Sequence)) => {}
                    _ => return None,
                }

                {
                    match reader.next() {
                        Ok(Some(DerType::Other(DerClass::ContextSpecific, 0))) => {}
                        _ => return None,
                    }

                    match reader.next() {
                        Ok(Some(DerType::Sequence)) => {}
                        _ => return None,
                    }

                    {
                        md = match reader.next() {
                            Ok(Some(DerType::ObjectIdentifier)) => {
                                match reader.to_object_identifier() {
                                    Ok(val) if val == *OID_SHA256 => MessageDigest::Sha256,
                                    Ok(val) if val == *OID_SHA384 => MessageDigest::Sha384,
                                    Ok(val) if val == *OID_SHA512 => MessageDigest::Sha512,
                                    _ => return None,
                                }
                            }
                            _ => return None,
                        }
                    }

                    match reader.next() {
                        Ok(Some(DerType::EndOfContents)) => {}
                        _ => return None,
                    }

                    match reader.next() {
                        Ok(Some(DerType::Other(DerClass::ContextSpecific, 1))) => {}
                        _ => return None,
                    }

                    match reader.next() {
                        Ok(Some(DerType::Sequence)) => {}
                        _ => return None,
                    }

                    {
                        match reader.next() {
                            Ok(Some(DerType::ObjectIdentifier)) => {
                                match reader.to_object_identifier() {
                                    Ok(val) => {
                                        if val != *OID_MGF1 {
                                            return None;
                                        }
                                    }
                                    _ => return None,
                                }
                            }
                            _ => return None,
                        }

                        match reader.next() {
                            Ok(Some(DerType::Sequence)) => {}
                            _ => return None,
                        }

                        {
                            mgf1_md = match reader.next() {
                                Ok(Some(DerType::ObjectIdentifier)) => {
                                    match reader.to_object_identifier() {
                                        Ok(val) if val == *OID_SHA256 => MessageDigest::Sha256,
                                        Ok(val) if val == *OID_SHA384 => MessageDigest::Sha384,
                                        Ok(val) if val == *OID_SHA512 => MessageDigest::Sha512,
                                        _ => return None,
                                    }
                                }
                                _ => return None,
                            }
                        }
                    }

                    match reader.next() {
                        Ok(Some(DerType::EndOfContents)) => {}
                        _ => return None,
                    }

                    match reader.next() {
                        Ok(Some(DerType::Other(DerClass::ContextSpecific, 2))) => {}
                        _ => return None,
                    }

                    salt_len = match reader.next() {
                        Ok(Some(DerType::Integer)) => match reader.to_u8() {
                            Ok(val) => val,
                            _ => return None,
                        },
                        _ => return None,
                    }
                }
            }
        }

        Some((md, mgf1_md, salt_len))
    }

    pub(crate) fn to_pkcs8(
        input: &[u8],
        is_public: bool,
        md: MessageDigest,
        mgf1_md: MessageDigest,
        salt_len: u8,
    ) -> Vec<u8> {
        let mut builder = DerBuilder::new();
        builder.begin(DerType::Sequence);
        {
            if !is_public {
                builder.append_integer_from_u8(0);
            }

            builder.begin(DerType::Sequence);
            {
                builder.append_object_identifier(&OID_RSASSA_PSS);
                builder.begin(DerType::Sequence);
                {
                    builder.begin(DerType::Other(DerClass::ContextSpecific, 0));
                    {
                        builder.begin(DerType::Sequence);
                        {
                            builder.append_object_identifier(match md {
                                MessageDigest::Sha256 => &OID_SHA256,
                                MessageDigest::Sha384 => &OID_SHA384,
                                MessageDigest::Sha512 => &OID_SHA512,
                            });
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
                                builder.append_object_identifier(match mgf1_md {
                                    MessageDigest::Sha256 => &OID_SHA256,
                                    MessageDigest::Sha384 => &OID_SHA384,
                                    MessageDigest::Sha512 => &OID_SHA512,
                                });
                            }
                            builder.end();
                        }
                        builder.end();
                    }
                    builder.end();

                    builder.begin(DerType::Other(DerClass::ContextSpecific, 2));
                    {
                        builder.append_integer_from_u8(salt_len);
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
}

impl KeyPair for RsaPssKeyPair {
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
        Self::to_pkcs8(
            &self.to_raw_private_key(),
            false,
            self.md,
            self.mgf1_md,
            self.salt_len,
        )
    }

    fn to_der_public_key(&self) -> Vec<u8> {
        Self::to_pkcs8(
            &self.to_raw_public_key(),
            true,
            self.md,
            self.mgf1_md,
            self.salt_len,
        )
    }

    fn to_pem_private_key(&self) -> Vec<u8> {
        let der = self.to_der_private_key();
        let der = base64::encode_config(&der, base64::STANDARD);

        let mut result = String::new();
        result.push_str("-----BEGIN PRIVATE KEY-----\r\n");
        for i in 0..((der.len() + 64 - 1) / 64) {
            result.push_str(&der[(i * 64)..std::cmp::min((i + 1) * 64, der.len())]);
            result.push_str("\r\n");
        }
        result.push_str("-----END PRIVATE KEY-----\r\n");
        result.into_bytes()
    }

    fn to_pem_public_key(&self) -> Vec<u8> {
        let der = self.to_der_public_key();
        let der = base64::encode_config(&der, base64::STANDARD);

        let mut result = String::new();
        result.push_str("-----BEGIN PUBLIC KEY-----\r\n");
        for i in 0..((der.len() + 64 - 1) / 64) {
            result.push_str(&der[(i * 64)..std::cmp::min((i + 1) * 64, der.len())]);
            result.push_str("\r\n");
        }
        result.push_str("-----END PUBLIC KEY-----\r\n");
        result.into_bytes()
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

impl Deref for RsaPssKeyPair {
    type Target = dyn KeyPair;

    fn deref(&self) -> &Self::Target {
        self
    }
}

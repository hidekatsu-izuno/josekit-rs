use std::ops::Deref;

use anyhow::bail;

use crate::jwk::{alg::rsapss::RsaPssKeyPair, Jwk, KeyPair, PrivateKey};
use crate::util::der::{DerBuilder, DerReader, DerType};
use crate::util::oid::OID_RSA_ENCRYPTION;
use crate::util::{self, HashAlgorithm};
use crate::{JoseError, Value};

#[derive(Debug, Clone)]
pub struct RsaKeyPair {
    private_key: PrivateKey,
    algorithm: Option<String>,
    key_id: Option<String>,
}

impl RsaKeyPair {
    pub fn key_len(&self) -> u32 {
        self.private_key.rsa_size().unwrap().try_into().unwrap()
    }

    pub fn set_algorithm(&mut self, value: Option<&str>) {
        self.algorithm = value.map(|val| val.to_string());
    }

    pub fn set_key_id(&mut self, key_id: Option<impl Into<String>>) {
        match key_id {
            Some(val) => {
                self.key_id = Some(val.into());
            }
            None => {
                self.key_id = None;
            }
        }
    }

    pub fn into_rsa_pss_key_pair(
        self,
        hash: HashAlgorithm,
        mgf1_hash: HashAlgorithm,
        salt_len: u8,
    ) -> RsaPssKeyPair {
        RsaPssKeyPair::from_private_key(self.private_key, hash, mgf1_hash, salt_len)
    }

    pub(crate) fn from_private_key(private_key: PrivateKey) -> Self {
        Self {
            private_key,
            algorithm: None,
            key_id: None,
        }
    }

    pub(crate) fn into_private_key(self) -> PrivateKey {
        self.private_key
    }

    /// Generate RSA key pair.
    ///
    /// # Arguments
    /// * `bits` - RSA key length
    pub fn generate(bits: u32) -> Result<RsaKeyPair, JoseError> {
        (|| -> anyhow::Result<RsaKeyPair> {
            let private_key = PrivateKey::generate_rsa(bits)?;

            Ok(RsaKeyPair {
                private_key,
                algorithm: None,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Create a RSA key pair from a private key that is a DER encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey.
    pub fn from_der(input: impl AsRef<[u8]>) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let pkcs8_der_vec;
            let pkcs8_der = match Self::detect_pkcs8(input.as_ref(), false) {
                Some(_) => input.as_ref(),
                None => {
                    pkcs8_der_vec = Self::to_pkcs8(input.as_ref(), false);
                    pkcs8_der_vec.as_slice()
                }
            };

            let private_key = PrivateKey::from_der(pkcs8_der, &OID_RSA_ENCRYPTION)?;

            Ok(Self {
                private_key,
                algorithm: None,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Create a RSA key pair from a private key of common or traditinal PEM format.
    ///
    /// Common PEM format is a DER and base64 encoded PKCS#8 PrivateKeyInfo
    /// that surrounded by "-----BEGIN/END PRIVATE KEY----".
    ///
    /// Traditional PEM format is a DER and base64 encoded PKCS#1 RSAPrivateKey
    /// that surrounded by "-----BEGIN/END RSA PRIVATE KEY----".
    ///
    /// # Arguments
    /// * `input` - A private key of common or traditinal PEM format.
    pub fn from_pem(input: impl AsRef<[u8]>) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            let (alg, data) = util::parse_pem(input.as_ref())?;

            let pkcs8_der_vec;
            let pkcs8_der = match alg.as_str() {
                "PRIVATE KEY" => match Self::detect_pkcs8(&data, false) {
                    Some(_) => data.as_slice(),
                    None => bail!("Invalid PEM contents."),
                },
                "RSA PRIVATE KEY" => {
                    pkcs8_der_vec = Self::to_pkcs8(&data, false);
                    pkcs8_der_vec.as_slice()
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };

            let private_key = PrivateKey::from_der(&pkcs8_der, &OID_RSA_ENCRYPTION)?;

            Ok(Self {
                private_key,
                algorithm: None,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Create a RSA key pair from a private key that is formatted by a JWK of RSA type.
    ///
    /// # Arguments
    /// * `jwk` - A private key that is formatted by a JWK of RSA type.
    pub fn from_jwk(jwk: &Jwk) -> Result<Self, JoseError> {
        (|| -> anyhow::Result<Self> {
            match jwk.key_type() {
                val if val == "RSA" => {}
                val => bail!("A parameter kty must be RSA: {}", val),
            }
            let n = match jwk.parameter("n") {
                Some(Value::String(val)) => util::decode_base64_urlsafe_no_pad(val)?,
                Some(_) => bail!("A parameter n must be a string."),
                None => bail!("A parameter n is required."),
            };
            let e = match jwk.parameter("e") {
                Some(Value::String(val)) => util::decode_base64_urlsafe_no_pad(val)?,
                Some(_) => bail!("A parameter e must be a string."),
                None => bail!("A parameter e is required."),
            };
            let d = match jwk.parameter("d") {
                Some(Value::String(val)) => util::decode_base64_urlsafe_no_pad(val)?,
                Some(_) => bail!("A parameter d must be a string."),
                None => bail!("A parameter d is required."),
            };
            let p = match jwk.parameter("p") {
                Some(Value::String(val)) => util::decode_base64_urlsafe_no_pad(val)?,
                Some(_) => bail!("A parameter p must be a string."),
                None => bail!("A parameter p is required."),
            };
            let q = match jwk.parameter("q") {
                Some(Value::String(val)) => util::decode_base64_urlsafe_no_pad(val)?,
                Some(_) => bail!("A parameter q must be a string."),
                None => bail!("A parameter q is required."),
            };
            let dp = match jwk.parameter("dp") {
                Some(Value::String(val)) => util::decode_base64_urlsafe_no_pad(val)?,
                Some(_) => bail!("A parameter dp must be a string."),
                None => bail!("A parameter dp is required."),
            };
            let dq = match jwk.parameter("dq") {
                Some(Value::String(val)) => util::decode_base64_urlsafe_no_pad(val)?,
                Some(_) => bail!("A parameter dq must be a string."),
                None => bail!("A parameter dq is required."),
            };
            let qi = match jwk.parameter("qi") {
                Some(Value::String(val)) => util::decode_base64_urlsafe_no_pad(val)?,
                Some(_) => bail!("A parameter qi must be a string."),
                None => bail!("A parameter qi is required."),
            };

            let mut builder = DerBuilder::new();
            builder.begin(DerType::Sequence);
            {
                builder.append_integer_from_u8(0); // version
                builder.append_integer_from_be_slice(&n, true); // n
                builder.append_integer_from_be_slice(&e, true); // e
                builder.append_integer_from_be_slice(&d, true); // d
                builder.append_integer_from_be_slice(&p, true); // p
                builder.append_integer_from_be_slice(&q, true); // q
                builder.append_integer_from_be_slice(&dp, true); // d mod (p-1)
                builder.append_integer_from_be_slice(&dq, true); // d mod (q-1)
                builder.append_integer_from_be_slice(&qi, true); // (inverse of q) mod p
            }
            builder.end();

            let pkcs8 = Self::to_pkcs8(&builder.build(), false);
            let private_key = PrivateKey::from_der(&pkcs8, &OID_RSA_ENCRYPTION)?;
            let algorithm = jwk.algorithm().map(|val| val.to_string());
            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(Self {
                private_key,
                algorithm,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn to_raw_private_key(&self) -> Vec<u8> {
        self.private_key.rsa_private_der()
    }

    pub fn to_traditional_pem_private_key(&self) -> Vec<u8> {
        #[cfg(not(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs")))]
        return self
            .private_key
            .openssl_rsa()
            .unwrap()
            .private_key_to_pem()
            .unwrap();
        #[cfg(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))]
        util::encode_pem("RSA PRIVATE KEY", &self.to_raw_private_key())
    }

    pub fn to_raw_public_key(&self) -> Vec<u8> {
        self.private_key.rsa_public_der()
    }

    pub fn to_traditional_pem_public_key(&self) -> Vec<u8> {
        #[cfg(not(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs")))]
        return self
            .private_key
            .openssl_rsa()
            .unwrap()
            .public_key_to_pem_pkcs1()
            .unwrap();
        #[cfg(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))]
        util::encode_pem("RSA PUBLIC KEY", &self.to_raw_public_key())
    }

    fn to_jwk(&self, private: bool, _public: bool) -> Jwk {
        let mut jwk = Jwk::new("RSA");
        if let Some(val) = &self.algorithm {
            jwk.set_algorithm(val);
        }
        if let Some(val) = &self.key_id {
            jwk.set_key_id(val);
        }
        let der = if private {
            self.to_raw_private_key()
        } else {
            self.to_raw_public_key()
        };
        set_rsa_jwk_parameters(&mut jwk, &der, private);

        jwk
    }

    pub(crate) fn detect_pkcs8(input: impl AsRef<[u8]>, is_public: bool) -> Option<()> {
        let mut reader = DerReader::from_reader(input.as_ref());

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
                builder.append_bit_string_from_bytes(input, 0);
            } else {
                builder.append_octed_string_from_bytes(input);
            }
        }
        builder.end();

        builder.build()
    }
}

pub(super) fn set_rsa_jwk_parameters(jwk: &mut Jwk, der: &[u8], private: bool) {
    let mut reader = DerReader::from_reader(der);
    assert_eq!(reader.next().unwrap(), Some(DerType::Sequence));
    let mut parameters: &[&str] = &["n", "e"];
    if private {
        assert_eq!(reader.next().unwrap(), Some(DerType::Integer)); // Version
        parameters = &["n", "e", "d", "p", "q", "dp", "dq", "qi"];
    }
    for &name in parameters {
        assert_eq!(reader.next().unwrap(), Some(DerType::Integer));
        let bytes = reader.to_be_bytes(false, 0);
        jwk.set_parameter(
            name,
            Some(Value::String(util::encode_base64_urlsafe_nopad(bytes))),
        )
        .unwrap();
    }
}

impl KeyPair for RsaKeyPair {
    fn algorithm(&self) -> Option<&str> {
        match &self.algorithm {
            Some(val) => Some(val.as_str()),
            None => None,
        }
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_str()),
            None => None,
        }
    }

    fn to_der_private_key(&self) -> Vec<u8> {
        Self::to_pkcs8(&self.to_raw_private_key(), false)
    }

    fn to_der_public_key(&self) -> Vec<u8> {
        self.private_key.to_der_public_key()
    }

    fn to_pem_private_key(&self) -> Vec<u8> {
        self.private_key.to_pem_private_key()
    }

    fn to_pem_public_key(&self) -> Vec<u8> {
        self.private_key.to_pem_public_key()
    }

    fn to_jwk_private_key(&self) -> Jwk {
        self.to_jwk(true, false)
    }

    fn to_jwk_public_key(&self) -> Jwk {
        self.to_jwk(false, true)
    }

    fn to_jwk_key_pair(&self) -> Jwk {
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

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::RsaKeyPair;

    #[test]
    fn test_rsa_jwt() -> Result<()> {
        for bits in vec![1024, 2048, 4096] {
            let key_pair_1 = RsaKeyPair::generate(bits)?;
            let der_private1 = key_pair_1.to_der_private_key();
            let der_public1 = key_pair_1.to_der_public_key();

            let jwk_key_pair_1 = key_pair_1.to_jwk_key_pair();

            let key_pair_2 = RsaKeyPair::from_jwk(&jwk_key_pair_1)?;
            let der_private2 = key_pair_2.to_der_private_key();
            let der_public2 = key_pair_2.to_der_public_key();

            assert_eq!(der_private1, der_private2);
            assert_eq!(der_public1, der_public2);
        }

        Ok(())
    }
}

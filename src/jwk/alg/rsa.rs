use std::ops::Deref;

use anyhow::bail;
#[cfg(feature = "openssl")]
use openssl::pkey::{PKey, Private};
#[cfg(feature = "openssl")]
use openssl::rsa::Rsa;
#[cfg(feature = "rustcrypto")]
use rsa::pkcs8::der::Decode;
#[cfg(feature = "rustcrypto")]
use rsa::pkcs8::DecodePrivateKey;
#[cfg(feature = "rustcrypto")]
use rsa::pkcs8::PrivateKeyInfoRef;
#[cfg(feature = "rustcrypto")]
use rsa::traits::{PrivateKeyParts, PublicKeyParts};

#[cfg(feature = "rustcrypto")]
use crate::jwk::PublicKey as PublicKeyTrait;
use crate::jwk::{alg::rsapss::RsaPssKeyPair, Jwk, KeyPair};
use crate::util::der::{DerBuilder, DerReader, DerType};
use crate::util::oid::OID_RSA_ENCRYPTION;
use crate::util::{self, HashAlgorithm};
use crate::{JoseError, Value};

#[derive(Debug, Clone)]
pub struct RsaKeyPair {
    #[cfg(feature = "openssl")]
    private_key: PKey<Private>,
    #[cfg(feature = "rustcrypto")]
    private_key: rsa::RsaPrivateKey,
    algorithm: Option<String>,
    key_id: Option<String>,
}

impl RsaKeyPair {
    pub fn key_len(&self) -> u32 {
        self.private_key.size().try_into().unwrap()
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

    #[cfg(feature = "openssl")]
    pub(crate) fn from_private_key(private_key: PKey<Private>) -> Self {
        Self {
            private_key,
            algorithm: None,
            key_id: None,
        }
    }
    #[cfg(feature = "rustcrypto")]
    pub(crate) fn from_private_key(private_key: rsa::RsaPrivateKey) -> Self {
        Self {
            private_key,
            algorithm: None,
            key_id: None,
        }
    }
    #[cfg(feature = "openssl")]
    pub(crate) fn into_private_key(self) -> PKey<Private> {
        self.private_key
    }
    #[cfg(feature = "rustcrypto")]
    pub(crate) fn into_private_key(self) -> rsa::RsaPrivateKey {
        self.private_key
    }

    /// Generate RSA key pair.
    ///
    /// # Arguments
    /// * `bits` - RSA key length
    pub fn generate(bits: u32) -> Result<RsaKeyPair, JoseError> {
        (|| -> anyhow::Result<RsaKeyPair> {
            #[cfg(feature = "openssl")]
            let rsa = Rsa::generate(bits)?;
            #[cfg(feature = "openssl")]
            let private_key = PKey::from_rsa(rsa)?;
            #[cfg(feature = "rustcrypto")]
            let private_key = rsa::RsaPrivateKey::new(&mut rand::rng(), bits as usize)?;
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

            #[cfg(feature = "openssl")]
            let private_key = PKey::private_key_from_der(pkcs8_der)?;
            #[cfg(feature = "rustcrypto")]
            let private_key = rsa::RsaPrivateKey::from_pkcs8_der(pkcs8_der)?;

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

            #[cfg(feature = "openssl")]
            let private_key = PKey::private_key_from_der(pkcs8_der)?;
            #[cfg(feature = "rustcrypto")]
            let private_key = rsa::RsaPrivateKey::from_pkcs8_der(pkcs8_der)?;

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
            #[cfg(feature = "rustcrypto")]
            let _ = PrivateKeyInfoRef::from_der(&pkcs8)?;
            #[cfg(feature = "openssl")]
            let private_key = PKey::private_key_from_der(&pkcs8)?;
            #[cfg(feature = "rustcrypto")]
            let private_key = rsa::RsaPrivateKey::from_pkcs8_der(&pkcs8)?;
            println!("--> after");
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

    #[cfg(feature = "openssl")]
    pub fn to_raw_private_key(&self) -> Vec<u8> {
        let rsa = self.private_key.rsa().unwrap();
        rsa.private_key_to_der().unwrap()
    }
    #[cfg(feature = "rustcrypto")]
    pub fn to_raw_private_key(&self) -> Vec<u8> {
        use rsa::pkcs1::EncodeRsaPrivateKey;
        self.private_key.to_pkcs1_der().unwrap().as_bytes().to_vec()
    }
    #[cfg(feature = "openssl")]
    pub fn to_traditional_pem_private_key(&self) -> Vec<u8> {
        let rsa = self.private_key.rsa().unwrap();
        rsa.private_key_to_pem().unwrap()
    }
    #[cfg(feature = "rustcrypto")]
    pub fn to_traditional_pem_private_key(&self) -> Vec<u8> {
        use rsa::{pkcs1::EncodeRsaPrivateKey, pkcs8::LineEnding};

        self.private_key
            .to_pkcs1_pem(LineEnding::CRLF)
            .unwrap()
            .as_bytes()
            .to_vec()
    }
    #[cfg(feature = "openssl")]
    pub fn to_raw_public_key(&self) -> Vec<u8> {
        let rsa = self.private_key.rsa().unwrap();
        rsa.public_key_to_der_pkcs1().unwrap()
    }
    #[cfg(feature = "rustcrypto")]
    pub fn to_raw_public_key(&self) -> Vec<u8> {
        use rsa::pkcs8::EncodePublicKey;

        self.private_key
            .to_public_key()
            .to_public_key_der()
            .unwrap()
            .to_vec()
    }
    #[cfg(feature = "openssl")]
    pub fn to_traditional_pem_public_key(&self) -> Vec<u8> {
        let rsa = self.private_key.rsa().unwrap();
        rsa.public_key_to_pem_pkcs1().unwrap()
    }
    #[cfg(feature = "rustcrypto")]
    pub fn to_traditional_pem_public_key(&self) -> Vec<u8> {
        use rsa::{pkcs8::EncodePublicKey, pkcs8::LineEnding};

        self.private_key
            .to_public_key()
            .to_public_key_pem(LineEnding::CRLF)
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    fn to_jwk(&self, private: bool, _public: bool) -> Jwk {
        #[cfg(feature = "openssl")]
        let rsa = self.private_key.rsa().unwrap();

        let mut jwk = Jwk::new("RSA");
        if let Some(val) = &self.algorithm {
            jwk.set_algorithm(val);
        }
        if let Some(val) = &self.key_id {
            jwk.set_key_id(val);
        }
        #[cfg(feature = "openssl")]
        let n = rsa.n().to_vec();
        #[cfg(feature = "rustcrypto")]
        let n = self.private_key.n().to_be_bytes_trimmed_vartime();
        let n = util::encode_base64_urlsafe_nopad(n);
        jwk.set_parameter("n", Some(Value::String(n))).unwrap();

        #[cfg(feature = "openssl")]
        let e = rsa.e().to_vec();
        #[cfg(feature = "rustcrypto")]
        let e = self.private_key.e().to_be_bytes_trimmed_vartime();
        let e = util::encode_base64_urlsafe_nopad(e);
        jwk.set_parameter("e", Some(Value::String(e))).unwrap();

        if private {
            #[cfg(feature = "openssl")]
            let d = rsa.d().to_vec();
            #[cfg(feature = "rustcrypto")]
            let d = self.private_key.d().to_be_bytes_trimmed_vartime();
            let d = util::encode_base64_urlsafe_nopad(d);
            jwk.set_parameter("d", Some(Value::String(d))).unwrap();

            #[cfg(feature = "openssl")]
            let p = rsa.p().unwrap().to_vec();
            #[cfg(feature = "rustcrypto")]
            let p = self.private_key.primes()[0].to_be_bytes_trimmed_vartime();
            let p = util::encode_base64_urlsafe_nopad(p);
            jwk.set_parameter("p", Some(Value::String(p))).unwrap();

            #[cfg(feature = "openssl")]
            let q = rsa.q().unwrap().to_vec();
            #[cfg(feature = "rustcrypto")]
            let q = self.private_key.primes()[1].to_be_bytes_trimmed_vartime();
            let q = util::encode_base64_urlsafe_nopad(q);
            jwk.set_parameter("q", Some(Value::String(q))).unwrap();

            #[cfg(feature = "openssl")]
            let dp = rsa.dmp1().unwrap().to_vec();
            #[cfg(feature = "rustcrypto")]
            let dp = self.private_key.dp().unwrap().to_be_bytes_trimmed_vartime();
            let dp = util::encode_base64_urlsafe_nopad(dp);
            jwk.set_parameter("dp", Some(Value::String(dp))).unwrap();
            #[cfg(feature = "openssl")]
            let dq = rsa.dmq1().unwrap().to_vec();
            #[cfg(feature = "rustcrypto")]
            let dq = self.private_key.dq().unwrap().to_be_bytes_trimmed_vartime();
            let dq = util::encode_base64_urlsafe_nopad(dq);
            jwk.set_parameter("dq", Some(Value::String(dq))).unwrap();

            #[cfg(feature = "openssl")]
            let qi = rsa.iqmp().unwrap().to_vec();
            #[cfg(feature = "rustcrypto")]
            let qi = self
                .private_key
                .qinv()
                .unwrap()
                .as_montgomery()
                .to_be_bytes_trimmed_vartime();
            let qi = util::encode_base64_urlsafe_nopad(qi);
            jwk.set_parameter("qi", Some(Value::String(qi))).unwrap();
        }

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

    #[cfg(feature = "openssl")]
    fn to_der_public_key(&self) -> Vec<u8> {
        self.private_key.public_key_to_der().unwrap()
    }
    #[cfg(feature = "rustcrypto")]
    fn to_der_public_key(&self) -> Vec<u8> {
        use rsa::pkcs1::EncodeRsaPublicKey;
        self.private_key
            .to_public_key()
            .to_pkcs1_der()
            .unwrap()
            .into_vec()
    }
    #[cfg(feature = "openssl")]
    fn to_pem_private_key(&self) -> Vec<u8> {
        self.private_key.private_key_to_pem_pkcs8().unwrap()
    }
    #[cfg(feature = "rustcrypto")]
    fn to_pem_private_key(&self) -> Vec<u8> {
        use rsa::pkcs8::{EncodePrivateKey, LineEnding};
        self.private_key
            .to_pkcs8_pem(LineEnding::CRLF)
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    #[cfg(feature = "openssl")]
    fn to_pem_public_key(&self) -> Vec<u8> {
        self.private_key.public_key_to_pem().unwrap()
    }
    #[cfg(feature = "rustcrypto")]
    fn to_pem_public_key(&self) -> Vec<u8> {
        use rsa::{pkcs1::EncodeRsaPublicKey, pkcs8::LineEnding};

        self.private_key
            .to_public_key()
            .to_pkcs1_pem(LineEnding::CRLF)
            .unwrap()
            .into_bytes()
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

#[cfg(feature = "rustcrypto")]
impl PublicKeyTrait for rsa::RsaPublicKey {
    fn to_der_public_key(&self) -> Vec<u8> {
        use rsa::pkcs1::EncodeRsaPublicKey;
        self.to_pkcs1_der().unwrap().into_vec()
    }

    fn to_pem_public_key(&self) -> Vec<u8> {
        use rsa::{pkcs1::EncodeRsaPublicKey, pkcs8::LineEnding};
        self.to_pkcs1_pem(LineEnding::CRLF).unwrap().into_bytes()
    }

    fn to_jwk_public_key(&self) -> Jwk {
        let mut jwk = Jwk::new("RSA");
        jwk.set_parameter(
            "n",
            Some(Value::String(util::encode_base64_urlsafe_nopad(
                self.n().to_be_bytes_trimmed_vartime(),
            ))),
        )
        .unwrap();
        jwk.set_parameter(
            "e",
            Some(Value::String(util::encode_base64_urlsafe_nopad(
                self.e().to_be_bytes_trimmed_vartime(),
            ))),
        )
        .unwrap();
        jwk
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

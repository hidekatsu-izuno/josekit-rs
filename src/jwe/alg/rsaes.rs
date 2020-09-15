use std::borrow::Cow;
use std::fmt::Display;
use std::ops::Deref;

use anyhow::bail;
use openssl::pkey::{PKey, Private, Public};
use openssl::hash::MessageDigest;
use openssl::rand;
use openssl::rsa::Padding;
use serde_json::Value;

use crate::der::{DerBuilder, DerType};
use crate::jwe::{JweAlgorithm, JweDecrypter, JweEncrypter, JweHeader};
use crate::jwk::{alg::rsa::RsaKeyPair, Jwk};
use crate::util;
use crate::JoseError;

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
    /// Generate RSA key pair.
    ///
    /// # Arguments
    /// * `bits` - RSA key length
    pub fn generate_keypair(&self, bits: u32) -> Result<RsaKeyPair, JoseError> {
        (|| -> anyhow::Result<RsaKeyPair> {
            if bits < 2048 {
                bail!("key length must be 2048 or more.");
            }

            let mut keypair = RsaKeyPair::generate(bits)?;
            keypair.set_algorithm(Some(self.name()));
            Ok(keypair)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidKeyFormat(err),
        })
    }

    /// Create a RSA key pair from a private key that is a DER encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey.
    pub fn keypair_from_der(&self, input: impl AsRef<[u8]>) -> Result<RsaKeyPair, JoseError> {
        (|| -> anyhow::Result<RsaKeyPair> {
            let mut keypair = RsaKeyPair::from_der(input)?;

            if keypair.key_len() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

            keypair.set_algorithm(Some(self.name()));
            Ok(keypair)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidKeyFormat(err),
        })
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
    pub fn keypair_from_pem(&self, input: impl AsRef<[u8]>) -> Result<RsaKeyPair, JoseError> {
        (|| -> anyhow::Result<RsaKeyPair> {
            let mut keypair = RsaKeyPair::from_pem(input.as_ref())?;

            if keypair.key_len() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

            keypair.set_algorithm(Some(self.name()));
            Ok(keypair)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidKeyFormat(err),
        })
    }

    pub fn encrypter_from_der(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<RsaesJweEncrypter, JoseError> {
        (|| -> anyhow::Result<RsaesJweEncrypter> {
            let spki_der_vec;
            let spki_der = match RsaKeyPair::detect_pkcs8(input.as_ref(), true) {
                Some(_) => input.as_ref(),
                None => {
                    spki_der_vec = RsaKeyPair::to_pkcs8(input.as_ref(), true);
                    spki_der_vec.as_slice()
                }
            };

            let public_key = PKey::public_key_from_der(spki_der)?;

            let rsa = public_key.rsa()?;
            if rsa.size() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

            Ok(RsaesJweEncrypter {
                algorithm: self.clone(),
                public_key,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn encrypter_from_pem(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<RsaesJweEncrypter, JoseError> {
        (|| -> anyhow::Result<RsaesJweEncrypter> {
            let (alg, data) = util::parse_pem(input.as_ref())?;

            let public_key = match alg.as_str() {
                "PUBLIC KEY" => match RsaKeyPair::detect_pkcs8(&data, true) {
                    Some(_) => PKey::public_key_from_der(&data)?,
                    None => bail!("Invalid PEM contents."),
                },
                "RSA PUBLIC KEY" => {
                    let pkcs8 = RsaKeyPair::to_pkcs8(&data, true);
                    PKey::public_key_from_der(&pkcs8)?
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };

            let rsa = public_key.rsa()?;
            if rsa.size() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

            Ok(RsaesJweEncrypter {
                algorithm: self.clone(),
                public_key,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn encrypter_from_jwk(&self, jwk: &Jwk) -> Result<RsaesJweEncrypter, JoseError> {
        (|| -> anyhow::Result<RsaesJweEncrypter> {
            match jwk.key_type() {
                val if val == "RSA" => {}
                val => bail!("A parameter kty must be RSA: {}", val),
            }
            match jwk.key_use() {
                Some(val) if val == "enc" => {}
                None => {}
                Some(val) => bail!("A parameter use must be enc: {}", val),
            }
            if !jwk.is_for_key_operation("encrypt") {
                bail!("A parameter key_ops must contains encrypt.");
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

            let pkcs8 = RsaKeyPair::to_pkcs8(&builder.build(), true);
            let public_key = PKey::public_key_from_der(&pkcs8)?;

            let rsa = public_key.rsa()?;
            if rsa.size() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(RsaesJweEncrypter {
                algorithm: self.clone(),
                public_key,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    pub fn decrypter_from_der(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<RsaesJweDecrypter, JoseError> {
        let keypair = self.keypair_from_der(input.as_ref())?;
        Ok(RsaesJweDecrypter {
            algorithm: self.clone(),
            private_key: keypair.into_private_key(),
            key_id: None,
        })
    }

    pub fn decrypter_from_pem(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<RsaesJweDecrypter, JoseError> {
        let keypair = self.keypair_from_pem(input.as_ref())?;
        Ok(RsaesJweDecrypter {
            algorithm: self.clone(),
            private_key: keypair.into_private_key(),
            key_id: None,
        })
    }

    pub fn decrypter_from_jwk(&self, jwk: &Jwk) -> Result<RsaesJweDecrypter, JoseError> {
        (|| -> anyhow::Result<RsaesJweDecrypter> {
            match jwk.key_use() {
                Some(val) if val == "enc" => {}
                None => {}
                Some(val) => bail!("A parameter use must be enc: {}", val),
            }
            if !jwk.is_for_key_operation("decrypt") {
                bail!("A parameter key_ops must contains decrypt.");
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }

            let keypair = RsaKeyPair::from_jwk(&jwk)?;
            if keypair.key_len() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

            let private_key = keypair.into_private_key();
            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(RsaesJweDecrypter {
                algorithm: self.clone(),
                private_key,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
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

    fn box_clone(&self) -> Box<dyn JweAlgorithm> {
        Box::new(self.clone())
    }
}

impl Display for RsaesJweAlgorithm {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for RsaesJweAlgorithm {
    type Target = dyn JweAlgorithm;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct RsaesJweEncrypter {
    algorithm: RsaesJweAlgorithm,
    public_key: PKey<Public>,
    key_id: Option<String>,
}

impl RsaesJweEncrypter {
    pub fn set_key_id(&mut self, value: impl Into<String>) {
        self.key_id = Some(value.into());
    }

    pub fn remove_key_id(&mut self) {
        self.key_id = None;
    }
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

    #[allow(deprecated)]
    fn encrypt(
        &self,
        header: &mut JweHeader,
        key_len: usize,
    ) -> Result<(Cow<[u8]>, Option<Vec<u8>>), JoseError> {
        (|| -> anyhow::Result<(Cow<[u8]>, Option<Vec<u8>>)> {
            header.set_algorithm(self.algorithm.name());

            let mut key = vec![0; key_len];
            rand::rand_bytes(&mut key)?;

            let rsa = self.public_key.rsa()?;
            let encrypted_key = match self.algorithm {
                RsaesJweAlgorithm::Rsa1_5 => {
                    let mut encrypted_key = vec![0; rsa.size() as usize];
                    let len = rsa.public_encrypt(&key, &mut encrypted_key, Padding::PKCS1)?;
                    encrypted_key.truncate(len);
                    encrypted_key
                }
                RsaesJweAlgorithm::RsaOaep => {
                    let mut encrypted_key = vec![0; rsa.size() as usize];
                    let len = rsa.public_encrypt(&key, &mut encrypted_key, Padding::PKCS1_OAEP)?;
                    encrypted_key.truncate(len);
                    encrypted_key
                }
                RsaesJweAlgorithm::RsaOaep256 => {
                    openssl_rsa_oaep::pkey_public_encrypt(
                        &self.public_key,
                        &key,
                        MessageDigest::sha256()
                    )?
                }
                RsaesJweAlgorithm::RsaOaep384 => {
                    openssl_rsa_oaep::pkey_public_encrypt(
                        &self.public_key,
                        &key,
                        MessageDigest::sha384()
                    )?
                }
                RsaesJweAlgorithm::RsaOaep512 => {
                    openssl_rsa_oaep::pkey_public_encrypt(
                        &self.public_key,
                        &key,
                        MessageDigest::sha512()
                    )?
                }
            };
            
            Ok((Cow::Owned(key), Some(encrypted_key)))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn box_clone(&self) -> Box<dyn JweEncrypter> {
        Box::new(self.clone())
    }
}

impl Deref for RsaesJweEncrypter {
    type Target = dyn JweEncrypter;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct RsaesJweDecrypter {
    algorithm: RsaesJweAlgorithm,
    private_key: PKey<Private>,
    key_id: Option<String>,
}

impl RsaesJweDecrypter {
    pub fn set_key_id(&mut self, value: impl Into<String>) {
        self.key_id = Some(value.into());
    }

    pub fn remove_key_id(&mut self) {
        self.key_id = None;
    }
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

    #[allow(deprecated)]
    fn decrypt(
        &self,
        _header: &JweHeader,
        encrypted_key: Option<&[u8]>,
        key_len: usize,
    ) -> Result<Cow<[u8]>, JoseError> {
        (|| -> anyhow::Result<Cow<[u8]>> {
            let encrypted_key = match encrypted_key {
                Some(val) => val,
                None => bail!("A encrypted_key is required."),
            };

            let rsa = self.private_key.rsa()?;
            let key = match self.algorithm {
                RsaesJweAlgorithm::Rsa1_5 => {
                    let mut key = vec![0; rsa.size() as usize];
                    let len = rsa.private_decrypt(&encrypted_key, &mut key, Padding::PKCS1)?;
                    key.truncate(len);
                    key
                }
                RsaesJweAlgorithm::RsaOaep => {
                    let mut key = vec![0; rsa.size() as usize];
                    let len = rsa.private_decrypt(&encrypted_key, &mut key, Padding::PKCS1_OAEP)?;
                    key.truncate(len);
                    key
                }
                RsaesJweAlgorithm::RsaOaep256 => {
                    openssl_rsa_oaep::pkey_private_decrypt(
                        &self.private_key,
                        &encrypted_key,
                        MessageDigest::sha256()
                    )?
                }
                RsaesJweAlgorithm::RsaOaep384 => {
                    openssl_rsa_oaep::pkey_private_decrypt(
                        &self.private_key,
                        &encrypted_key,
                        MessageDigest::sha384()
                    )?
                }
                RsaesJweAlgorithm::RsaOaep512 => {
                    openssl_rsa_oaep::pkey_private_decrypt(
                        &self.private_key,
                        &encrypted_key,
                        MessageDigest::sha512()
                    )?
                }
            };

            if key.len() != key_len {
                bail!("The key size is expected to be {}: {}", key_len, key.len());
            }

            Ok(Cow::Owned(key))
        })()
        .map_err(|err| JoseError::InvalidJweFormat(err))
    }

    fn box_clone(&self) -> Box<dyn JweDecrypter> {
        Box::new(self.clone())
    }
}

impl Deref for RsaesJweDecrypter {
    type Target = dyn JweDecrypter;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use std::fs;
    use std::path::PathBuf;

    use super::RsaesJweAlgorithm;
    use crate::jwe::enc::aes_cbc_hmac::AesCbcHmacJweEncryption;
    use crate::jwe::JweHeader;
    use crate::jwk::Jwk;

    #[test]
    #[allow(deprecated)]
    fn encrypt_and_decrypt_rsaes() -> Result<()> {
        let enc = AesCbcHmacJweEncryption::A128CbcHS256;

        let private_key = load_file("jwk/RSA_private.jwk")?;
        let mut private_key = Jwk::from_bytes(&private_key)?;
        private_key.set_key_use("enc");

        let public_key = load_file("jwk/RSA_public.jwk")?;
        let mut public_key = Jwk::from_bytes(&public_key)?;
        public_key.set_key_use("enc");

        for alg in vec![
            RsaesJweAlgorithm::Rsa1_5,
            RsaesJweAlgorithm::RsaOaep,
            RsaesJweAlgorithm::RsaOaep256,
        ] {
            let mut header = JweHeader::new();
            header.set_content_encryption(enc.name());

            let encrypter = alg.encrypter_from_jwk(&public_key)?;
            let (src_key, encrypted_key) = encrypter.encrypt(&mut header, enc.key_len())?;

            let decrypter = alg.decrypter_from_jwk(&private_key)?;
            let dst_key = decrypter.decrypt(&header, encrypted_key.as_deref(), enc.key_len())?;

            assert_eq!(&src_key, &dst_key);
        }

        Ok(())
    }

    fn load_file(path: &str) -> Result<Vec<u8>> {
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push("data");
        pb.push(path);

        let data = fs::read(&pb)?;
        Ok(data)
    }
}

mod openssl_rsa_oaep {
    use std::os::raw::{c_int, c_void};
    use std::ptr;
    use openssl_sys::{
        EVP_PKEY_CTX,
        EVP_MD,
        EVP_PKEY_CTX_new,
        EVP_PKEY_CTX_free,
        EVP_PKEY_CTX_set_rsa_padding,
        EVP_PKEY_CTX_set_rsa_mgf1_md,
        EVP_PKEY_CTX_ctrl,
        EVP_PKEY_encrypt_init,
        EVP_PKEY_encrypt,
        EVP_PKEY_decrypt_init,
        EVP_PKEY_decrypt,
        EVP_PKEY_RSA,
        EVP_PKEY_OP_TYPE_CRYPT,
        EVP_PKEY_ALG_CTRL,
        RSA_PKCS1_OAEP_PADDING
    };
    use openssl::error::ErrorStack;
    use openssl::pkey::{PKey, Public, Private};
    use openssl::hash::MessageDigest;
    use foreign_types::ForeignType;

    pub(crate) fn pkey_public_encrypt(pkey: &PKey<Public>, input: &[u8], md: MessageDigest) -> Result<Vec<u8>, ErrorStack> {
        let mut output;
        unsafe {
            let k = pkey.as_ptr();
            let md = md.as_ptr();

            let ctx = match EVP_PKEY_CTX_new(k, ptr::null_mut()) {
                val if val.is_null() => return Err(ErrorStack::get()),
                val => val,
            };

            if EVP_PKEY_encrypt_init(ctx) <= 0
                || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0
                || EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md as *mut _) <= 0
                || EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md as *mut _) <= 0 {
                EVP_PKEY_CTX_free(ctx);
                return Err(ErrorStack::get());
            }

            let mut outlen = 0;
            if EVP_PKEY_encrypt(ctx, 
                ptr::null_mut(),
                &mut outlen,
                input.as_ptr(),
                input.len(),
            ) <= 0 {
                EVP_PKEY_CTX_free(ctx);
                return Err(ErrorStack::get());
            };

            output = vec![0; outlen];
            if EVP_PKEY_encrypt(ctx, 
                output.as_mut_ptr(),
                &mut outlen,
                input.as_ptr(),
                input.len(),
            ) <= 0 {
                EVP_PKEY_CTX_free(ctx);
                return Err(ErrorStack::get());
            };
            if outlen < output.len() {
                output.truncate(outlen);
            }

            EVP_PKEY_CTX_free(ctx);
        }

        Ok(output)
    }

    pub(crate) fn pkey_private_decrypt(pkey: &PKey<Private>, input: &[u8], md: MessageDigest) -> Result<Vec<u8>, ErrorStack> {
        let mut output;
        unsafe {
            let k = pkey.as_ptr();
            let md = md.as_ptr();

            let ctx = match EVP_PKEY_CTX_new(k, ptr::null_mut()) {
                val if val.is_null() => return Err(ErrorStack::get()),
                val => val,
            };

            if EVP_PKEY_decrypt_init(ctx) <= 0
                || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0
                || EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md as *mut _) <= 0
                || EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md as *mut _) <= 0 {
                EVP_PKEY_CTX_free(ctx);
                return Err(ErrorStack::get());
            }

            let mut outlen = 0;
            if EVP_PKEY_decrypt(ctx, 
                ptr::null_mut(),
                &mut outlen,
                input.as_ptr(),
                input.len(),
            ) <= 0 {
                EVP_PKEY_CTX_free(ctx);
                return Err(ErrorStack::get());
            };

            output = vec![0; outlen];
            if EVP_PKEY_decrypt(ctx, 
                output.as_mut_ptr(),
                &mut outlen,
                input.as_ptr(),
                input.len(),
            ) <= 0 {
                EVP_PKEY_CTX_free(ctx);
                return Err(ErrorStack::get());
            };
            if outlen < output.len() {
                output.truncate(outlen);
            }

            EVP_PKEY_CTX_free(ctx);
        }

        Ok(output)
    }

    const EVP_PKEY_CTRL_RSA_OAEP_MD: c_int = EVP_PKEY_ALG_CTRL + 9;

    #[allow(non_snake_case)]
    unsafe fn EVP_PKEY_CTX_set_rsa_oaep_md(ctx: *mut EVP_PKEY_CTX, md: *mut EVP_MD) -> c_int {
        EVP_PKEY_CTX_ctrl(
            ctx,
            EVP_PKEY_RSA, 
            EVP_PKEY_OP_TYPE_CRYPT,
            EVP_PKEY_CTRL_RSA_OAEP_MD,
            0,
            md as *mut c_void,
        )
    }
}
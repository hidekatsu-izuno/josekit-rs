use std::{fmt::Display, ops::Deref};

#[cfg(feature = "rustcrypto")]
use crate::jwe::alg::pbes2_hmac_aeskw::MessageDigest;
use crate::{jwe::JweContentEncryption, JoseError};
use anyhow::bail;
#[cfg(feature = "openssl")]
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
    sign::Signer,
    symm::{self, Cipher},
};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AescbcHmacJweEncryption {
    /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm
    A128cbcHs256,
    /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm
    A192cbcHs384,
    /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm
    A256cbcHs512,
}

impl AescbcHmacJweEncryption {
    fn calcurate_tag(
        &self,
        aad: &[u8],
        iv: Option<&[u8]>,
        ciphertext: &[u8],
        mac_key: &[u8],
    ) -> Result<Vec<u8>, JoseError> {
        let (message_digest, tlen) = match self {
            Self::A128cbcHs256 => (MessageDigest::sha256(), 16),
            Self::A192cbcHs384 => (MessageDigest::sha384(), 24),
            Self::A256cbcHs512 => (MessageDigest::sha512(), 32),
        };
        #[cfg(feature = "openssl")]
        let pkey = (|| -> anyhow::Result<PKey<Private>> {
            let pkey = PKey::hmac(mac_key)?;
            Ok(pkey)
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))?;

        let signature = (|| -> anyhow::Result<Vec<u8>> {
            let aad_bits = ((aad.len() * 8) as u64).to_be_bytes();
            #[cfg(feature = "openssl")]
            let mut signer = Signer::new(message_digest, &pkey)?;
            #[cfg(feature = "rustcrypto")]
            let mut signer = message_digest.hmac(mac_key)?;
            signer.update(aad)?;
            if let Some(val) = iv {
                signer.update(val)?;
            }
            signer.update(ciphertext)?;
            signer.update(&aad_bits)?;
            let mut signature = signer.sign_to_vec()?;
            signature.truncate(tlen);
            Ok(signature)
        })()
        .map_err(|err| JoseError::InvalidSignature(err))?;

        Ok(signature)
    }
}

impl JweContentEncryption for AescbcHmacJweEncryption {
    fn name(&self) -> &str {
        match self {
            Self::A128cbcHs256 => "A128CBC-HS256",
            Self::A192cbcHs384 => "A192CBC-HS384",
            Self::A256cbcHs512 => "A256CBC-HS512",
        }
    }

    fn key_len(&self) -> usize {
        match self {
            Self::A128cbcHs256 => 32,
            Self::A192cbcHs384 => 48,
            Self::A256cbcHs512 => 64,
        }
    }

    fn iv_len(&self) -> usize {
        16
    }

    fn encrypt(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        message: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), JoseError> {
        let (encrypted_message, mac_key) = (|| -> anyhow::Result<(Vec<u8>, &[u8])> {
            let expected_len = self.key_len();
            if key.len() != expected_len {
                bail!(
                    "The length of content encryption key must be {}: {}",
                    expected_len,
                    key.len()
                );
            }

            let mac_key_len = expected_len / 2;
            let mac_key = &key[0..mac_key_len];
            let enc_key = &key[mac_key_len..];
            #[cfg(feature = "openssl")]
            let cipher = match self {
                AescbcHmacJweEncryption::A128cbcHs256 => Cipher::aes_128_cbc(),
                AescbcHmacJweEncryption::A192cbcHs384 => Cipher::aes_192_cbc(),
                AescbcHmacJweEncryption::A256cbcHs512 => Cipher::aes_256_cbc(),
            };
            #[cfg(feature = "openssl")]
            let encrypted_message = symm::encrypt(cipher, enc_key, iv, message)?;
            #[cfg(feature = "rustcrypto")]
            let encrypted_message = match self {
                AescbcHmacJweEncryption::A128cbcHs256 => {
                    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
                    let mut default_iv = [0; 16];
                    if let Some(iv) = iv {
                        default_iv.copy_from_slice(&iv[..16]);
                    }
                    let encryptor =
                        cbc::Encryptor::<aes::Aes128>::new(enc_key.into(), &default_iv.into());
                    encryptor.encrypt_padded_vec_mut::<Pkcs7>(&message)
                }
                AescbcHmacJweEncryption::A192cbcHs384 => {
                    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
                    let mut default_iv = [0; 16];
                    if let Some(iv) = iv {
                        default_iv.copy_from_slice(&iv[..16]);
                    }
                    let encryptor =
                        cbc::Encryptor::<aes::Aes192>::new(enc_key.into(), &default_iv.into());
                    encryptor.encrypt_padded_vec_mut::<Pkcs7>(&message)
                }
                AescbcHmacJweEncryption::A256cbcHs512 => {
                    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
                    let mut default_iv = [0; 16];
                    if let Some(iv) = iv {
                        default_iv.copy_from_slice(&iv[..16]);
                    }
                    let encryptor =
                        cbc::Encryptor::<aes::Aes256>::new(enc_key.into(), &default_iv.into());
                    encryptor.encrypt_padded_vec_mut::<Pkcs7>(&message)
                }
            };
            Ok((encrypted_message, mac_key))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))?;

        let tag = self.calcurate_tag(aad, iv, &encrypted_message, mac_key)?;

        Ok((encrypted_message, Some(tag)))
    }

    fn decrypt(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        encrypted_message: &[u8],
        aad: &[u8],
        tag: Option<&[u8]>,
    ) -> Result<Vec<u8>, JoseError> {
        let (message, mac_key) = (|| -> anyhow::Result<(Vec<u8>, &[u8])> {
            let expected_len = self.key_len();
            if key.len() != expected_len {
                bail!(
                    "The length of content encryption key must be {}: {}",
                    expected_len,
                    key.len()
                );
            }

            let mac_key_len = expected_len / 2;
            let mac_key = &key[0..mac_key_len];
            let enc_key = &key[mac_key_len..];
            #[cfg(feature = "openssl")]
            let cipher = match self {
                AescbcHmacJweEncryption::A128cbcHs256 => Cipher::aes_128_cbc(),
                AescbcHmacJweEncryption::A192cbcHs384 => Cipher::aes_192_cbc(),
                AescbcHmacJweEncryption::A256cbcHs512 => Cipher::aes_256_cbc(),
            };
            #[cfg(feature = "openssl")]
            let message = symm::decrypt(cipher, enc_key, iv, encrypted_message)?;
            #[cfg(feature = "rustcrypto")]
            let message = match self {
                AescbcHmacJweEncryption::A128cbcHs256 => {
                    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
                    let mut default_iv = [0; 16];
                    if let Some(iv) = iv {
                        default_iv.copy_from_slice(&iv[..16]);
                    }
                    let decryptor =
                        cbc::Decryptor::<aes::Aes128>::new(enc_key.into(), &default_iv.into());
                    decryptor
                        .decrypt_padded_vec_mut::<Pkcs7>(&encrypted_message)
                        .map_err(|e| anyhow::anyhow!(e))?
                }
                AescbcHmacJweEncryption::A192cbcHs384 => {
                    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
                    let mut default_iv = [0; 16];
                    if let Some(iv) = iv {
                        default_iv.copy_from_slice(&iv[..16]);
                    }
                    let decryptor =
                        cbc::Decryptor::<aes::Aes192>::new(enc_key.into(), &default_iv.into());
                    decryptor
                        .decrypt_padded_vec_mut::<Pkcs7>(&encrypted_message)
                        .map_err(|e| anyhow::anyhow!(e))?
                }
                AescbcHmacJweEncryption::A256cbcHs512 => {
                    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
                    let mut default_iv = [0; 16];
                    if let Some(iv) = iv {
                        default_iv.copy_from_slice(&iv[..16]);
                    }
                    let decryptor =
                        cbc::Decryptor::<aes::Aes256>::new(enc_key.into(), &default_iv.into());
                    decryptor
                        .decrypt_padded_vec_mut::<Pkcs7>(encrypted_message)
                        .map_err(|e| anyhow::anyhow!(e))?
                }
            };
            Ok((message, mac_key))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))?;

        (|| -> anyhow::Result<()> {
            let tag = match tag {
                Some(val) => val,
                None => bail!("A tag value is required."),
            };

            let calc_tag = self.calcurate_tag(aad, iv, &encrypted_message, mac_key)?;
            if calc_tag.as_slice() != tag {
                bail!("The tag doesn't match.");
            }

            Ok(())
        })()
        .map_err(|err| JoseError::InvalidSignature(err))?;

        Ok(message)
    }

    fn box_clone(&self) -> Box<dyn JweContentEncryption> {
        Box::new(self.clone())
    }
}

impl Display for AescbcHmacJweEncryption {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for AescbcHmacJweEncryption {
    type Target = dyn JweContentEncryption;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::AescbcHmacJweEncryption;
    use crate::util;

    #[test]
    fn encrypt_and_decrypt_aes_cbc_hmac() -> Result<()> {
        let message = b"abcde12345";
        let aad = b"test";

        for enc in vec![
            AescbcHmacJweEncryption::A128cbcHs256,
            AescbcHmacJweEncryption::A192cbcHs384,
            AescbcHmacJweEncryption::A256cbcHs512,
        ] {
            let key = util::random_bytes(enc.key_len());
            let iv = util::random_bytes(enc.iv_len());

            let (encrypted_message, tag) = enc.encrypt(&key, Some(&iv), message, aad)?;
            let decrypted_message = enc.decrypt(
                &key,
                Some(&iv),
                &encrypted_message,
                &aad[..],
                tag.as_deref(),
            )?;

            assert_eq!(&message[..], &decrypted_message[..]);
        }

        Ok(())
    }
}

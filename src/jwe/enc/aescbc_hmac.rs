use std::{fmt::Display, ops::Deref};

use anyhow::bail;
#[cfg(not(any(feature = "aes-cbc-hmac-rustcrypto", feature = "aws-lc-rs")))]
use openssl::symm::{self, Cipher};

#[cfg(not(any(feature = "aes-cbc-hmac-rustcrypto", feature = "aws-lc-rs")))]
use crate::jwk::PrivateKey;
use crate::{jwe::JweContentEncryption, util::HashAlgorithm, JoseError};

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
    fn calculate_tag(
        &self,
        aad: &[u8],
        iv: &[u8],
        ciphertext: &[u8],
        mac_key: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let hash = match self {
            Self::A128cbcHs256 => HashAlgorithm::Sha256,
            Self::A192cbcHs384 => HashAlgorithm::Sha384,
            Self::A256cbcHs512 => HashAlgorithm::Sha512,
        };
        let aad_bits = (u64::try_from(aad.len())? * 8).to_be_bytes();
        let parts = [aad, iv, ciphertext, &aad_bits];

        #[cfg(feature = "aws-lc-rs")]
        let mut signature = crate::aws_lc::sign_hmac(hash, mac_key, &parts)?;
        #[cfg(not(any(feature = "aes-cbc-hmac-rustcrypto", feature = "aws-lc-rs")))]
        let mut signature = PrivateKey::openssl_hmac(mac_key, hash, &parts)?;
        #[cfg(all(feature = "aes-cbc-hmac-rustcrypto", not(feature = "aws-lc-rs")))]
        let mut signature = hash.hmac(mac_key, &parts)?;

        signature.truncate(self.key_len() / 2);
        Ok(signature)
    }

    fn parameters<'a, 'b>(
        &self,
        key: &'a [u8],
        iv: Option<&'b [u8]>,
    ) -> anyhow::Result<(&'a [u8], &'a [u8], &'b [u8])> {
        if key.len() != self.key_len() {
            bail!(
                "The length of content encryption key must be {}: {}",
                self.key_len(),
                key.len()
            );
        }
        let iv = iv
            .filter(|iv| iv.len() == self.iv_len())
            .ok_or_else(|| anyhow::anyhow!("The AES-CBC IV must be 16 bytes."))?;
        let (mac_key, enc_key) = key.split_at(key.len() / 2);
        Ok((mac_key, enc_key, iv))
    }

    #[cfg(not(any(feature = "aes-cbc-hmac-rustcrypto", feature = "aws-lc-rs")))]
    fn cipher(&self) -> Cipher {
        match self {
            Self::A128cbcHs256 => Cipher::aes_128_cbc(),
            Self::A192cbcHs384 => Cipher::aes_192_cbc(),
            Self::A256cbcHs512 => Cipher::aes_256_cbc(),
        }
    }

    #[cfg(all(feature = "aes-cbc-hmac-rustcrypto", not(feature = "aws-lc-rs")))]
    fn encrypt_cbc(&self, key: &[u8], iv: &[u8], message: &[u8]) -> anyhow::Result<Vec<u8>> {
        use cbc::cipher::{block_padding::Pkcs7, BlockModeEncrypt, KeyIvInit};

        let ciphertext = match self {
            Self::A128cbcHs256 => cbc::Encryptor::<aes::Aes128>::new_from_slices(key, iv)?
                .encrypt_padded_vec::<Pkcs7>(message),
            Self::A192cbcHs384 => cbc::Encryptor::<aes::Aes192>::new_from_slices(key, iv)?
                .encrypt_padded_vec::<Pkcs7>(message),
            Self::A256cbcHs512 => cbc::Encryptor::<aes::Aes256>::new_from_slices(key, iv)?
                .encrypt_padded_vec::<Pkcs7>(message),
        };
        Ok(ciphertext)
    }

    #[cfg(all(feature = "aes-cbc-hmac-rustcrypto", not(feature = "aws-lc-rs")))]
    fn decrypt_cbc(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        use cbc::cipher::{block_padding::Pkcs7, BlockModeDecrypt, KeyIvInit};

        let message = match self {
            Self::A128cbcHs256 => cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv)?
                .decrypt_padded_vec::<Pkcs7>(ciphertext),
            Self::A192cbcHs384 => cbc::Decryptor::<aes::Aes192>::new_from_slices(key, iv)?
                .decrypt_padded_vec::<Pkcs7>(ciphertext),
            Self::A256cbcHs512 => cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)?
                .decrypt_padded_vec::<Pkcs7>(ciphertext),
        };
        message.map_err(|_| anyhow::anyhow!("Invalid AES-CBC padding."))
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
        let (mac_key, enc_key, iv) = self
            .parameters(key, iv)
            .map_err(JoseError::InvalidKeyFormat)?;
        #[cfg(feature = "aws-lc-rs")]
        let ciphertext = crate::aws_lc::encrypt_cbc(enc_key, iv, message);
        #[cfg(not(any(feature = "aes-cbc-hmac-rustcrypto", feature = "aws-lc-rs")))]
        let ciphertext =
            symm::encrypt(self.cipher(), enc_key, Some(iv), message).map_err(anyhow::Error::from);
        #[cfg(all(feature = "aes-cbc-hmac-rustcrypto", not(feature = "aws-lc-rs")))]
        let ciphertext = self.encrypt_cbc(enc_key, iv, message);
        let ciphertext = ciphertext.map_err(JoseError::InvalidKeyFormat)?;

        let tag = self
            .calculate_tag(aad, iv, &ciphertext, mac_key)
            .map_err(JoseError::InvalidSignature)?;
        Ok((ciphertext, Some(tag)))
    }

    fn decrypt(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        encrypted_message: &[u8],
        aad: &[u8],
        tag: Option<&[u8]>,
    ) -> Result<Vec<u8>, JoseError> {
        let (mac_key, enc_key, iv) = self
            .parameters(key, iv)
            .map_err(JoseError::InvalidKeyFormat)?;

        (|| -> anyhow::Result<()> {
            let tag = tag.ok_or_else(|| anyhow::anyhow!("A tag value is required."))?;
            let expected = self.calculate_tag(aad, iv, encrypted_message, mac_key)?;
            #[cfg(feature = "aws-lc-rs")]
            let matches = aws_lc_rs::constant_time::verify_slices_are_equal(&expected, tag).is_ok();
            #[cfg(not(any(feature = "aes-cbc-hmac-rustcrypto", feature = "aws-lc-rs")))]
            let matches = expected.len() == tag.len() && openssl::memcmp::eq(&expected, tag);
            #[cfg(all(feature = "aes-cbc-hmac-rustcrypto", not(feature = "aws-lc-rs")))]
            let matches = {
                use subtle::ConstantTimeEq;
                bool::from(expected.ct_eq(tag))
            };
            if !matches {
                bail!("The tag doesn't match.");
            }
            Ok(())
        })()
        .map_err(JoseError::InvalidSignature)?;

        #[cfg(feature = "aws-lc-rs")]
        let message = crate::aws_lc::decrypt_cbc(enc_key, iv, encrypted_message);
        #[cfg(not(any(feature = "aes-cbc-hmac-rustcrypto", feature = "aws-lc-rs")))]
        let message = symm::decrypt(self.cipher(), enc_key, Some(iv), encrypted_message)
            .map_err(anyhow::Error::from);
        #[cfg(all(feature = "aes-cbc-hmac-rustcrypto", not(feature = "aws-lc-rs")))]
        let message = self.decrypt_cbc(enc_key, iv, encrypted_message);
        message.map_err(JoseError::InvalidKeyFormat)
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

            let mut bad_tag = tag.unwrap();
            bad_tag[0] ^= 1;
            assert!(matches!(
                enc.decrypt(
                    &key,
                    Some(&iv),
                    &encrypted_message[..1],
                    aad,
                    Some(&bad_tag)
                ),
                Err(crate::JoseError::InvalidSignature(_))
            ));
        }

        Ok(())
    }
}

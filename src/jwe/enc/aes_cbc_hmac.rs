use std::fmt::Display;
use std::ops::Deref;

use anyhow::bail;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use openssl::symm::{self, Cipher};

use crate::jose::JoseError;
use crate::jwe::JweContentEncryption;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AesCbcHmacJweEncryption {
    /// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm
    A128CbcHS256,
    /// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm
    A192CbcHS384,
    /// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm
    A256CbcHS512,
}

impl AesCbcHmacJweEncryption {
    fn cipher(&self) -> Cipher {
        match self {
            Self::A128CbcHS256 => Cipher::aes_128_cbc(),
            Self::A192CbcHS384 => Cipher::aes_192_cbc(),
            Self::A256CbcHS512 => Cipher::aes_256_cbc(),
        }
    }

    fn calcurate_tag(
        &self,
        aad: &[u8],
        iv: Option<&[u8]>,
        ciphertext: &[u8],
        mac_key: &[u8],
    ) -> Result<Vec<u8>, JoseError> {
        let (message_digest, tlen) = match self {
            Self::A128CbcHS256 => (MessageDigest::sha256(), 16),
            Self::A192CbcHS384 => (MessageDigest::sha384(), 24),
            Self::A256CbcHS512 => (MessageDigest::sha512(), 32),
        };

        let pkey = (|| -> anyhow::Result<PKey<Private>> {
            let pkey = PKey::hmac(mac_key)?;
            Ok(pkey)
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))?;

        let signature = (|| -> anyhow::Result<Vec<u8>> {
            let aad_bits = ((aad.len() * 8) as u64).to_be_bytes();

            let mut signer = Signer::new(message_digest, &pkey)?;
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

impl JweContentEncryption for AesCbcHmacJweEncryption {
    fn name(&self) -> &str {
        match self {
            Self::A128CbcHS256 => "A128CBC-HS256",
            Self::A192CbcHS384 => "A192CBC-HS384",
            Self::A256CbcHS512 => "A256CBC-HS512",
        }
    }

    fn key_len(&self) -> usize {
        match self {
            Self::A128CbcHS256 => 16 + 16,
            Self::A192CbcHS384 => 16 + 24,
            Self::A256CbcHS512 => 16 + 32,
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

            let mac_key = &key[0..16];
            let enc_key = &key[16..];

            let cipher = self.cipher();
            let encrypted_message = symm::encrypt(cipher, enc_key, iv, message)?;
            Ok((encrypted_message, mac_key))
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))?;

        let tag = self.calcurate_tag(aad, iv, message, mac_key)?;

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

            let mac_key = &key[0..16];
            let enc_key = &key[16..];

            let cipher = self.cipher();
            let message = symm::decrypt(cipher, enc_key, iv, encrypted_message)?;
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

impl Display for AesCbcHmacJweEncryption {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for AesCbcHmacJweEncryption {
    type Target = dyn JweContentEncryption;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::AesCbcHmacJweEncryption;
    use crate::util;

    #[test]
    fn encrypt_and_decrypt_aes_cbc_hmac() -> Result<()> {
        let message = b"abcde12345";
        let aad = b"test";

        for enc in vec![
            AesCbcHmacJweEncryption::A128CbcHS256,
            AesCbcHmacJweEncryption::A192CbcHS384,
            AesCbcHmacJweEncryption::A256CbcHS512,
        ] {
            let key = util::rand_bytes(enc.key_len());
            let iv = util::rand_bytes(enc.iv_len());

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

use openssl::pkey::{ PKey, Private };
use openssl::hash::MessageDigest;
use openssl::memcmp;
use anyhow::{ anyhow, bail };

use crate::algorithm::{ HashAlgorithm, Algorithm, Signer, Verifier };
use crate::error::JwtError;

pub struct HmacAlgorithm {
    hash_algorithm: HashAlgorithm
}

impl HmacAlgorithm {
    pub const fn new(hash_algorithm: HashAlgorithm) -> Self {
        HmacAlgorithm {
            hash_algorithm
        }
    }

    pub fn signer_from_bytes<'a>(&'a self, data: &[u8]) -> Result<impl Signer<HmacAlgorithm> + Verifier<HmacAlgorithm> + 'a, JwtError> {
        PKey::hmac(&data)
            .map_err(|err| {
                JwtError::InvalidKeyFormat(anyhow!(err))
            })
            .map(|val| {
                HmacSigner {
                    algorithm: &self,
                    private_key: val
                }
            })
    }
}

impl Algorithm for HmacAlgorithm {
    fn name(&self) -> &str {
        match self.hash_algorithm {
            HashAlgorithm::SHA256 => "HS256",
            HashAlgorithm::SHA384 => "HS384",
            HashAlgorithm::SHA512 => "HS512",
        }
    }
}

pub struct HmacSigner<'a> {
    algorithm: &'a HmacAlgorithm,
    private_key: PKey<Private>
}

impl<'a> Signer<HmacAlgorithm> for HmacSigner<'a> {
    fn algorithm(&self) -> &HmacAlgorithm {
        &self.algorithm
    }

    fn sign(&self, data: &[&[u8]]) -> Result<Vec<u8>, JwtError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let message_digest = match self.algorithm.hash_algorithm {
                HashAlgorithm::SHA256 => MessageDigest::sha256(),
                HashAlgorithm::SHA384 => MessageDigest::sha384(),
                HashAlgorithm::SHA512 => MessageDigest::sha512()
            };

            let mut signer = openssl::sign::Signer::new(message_digest, &self.private_key)?;
            for part in data {
                signer.update(part)?;
            }
            let signature = signer.sign_to_vec()?;
            Ok(signature)
        })().map_err(|err| {
            JwtError::InvalidSignature(err)
        })
    }
}

impl<'a> Verifier<HmacAlgorithm> for HmacSigner<'a> {
    fn algorithm(&self) -> &HmacAlgorithm {
        &self.algorithm
    }

    fn verify(&self, data: &[&[u8]], signature: &[u8]) -> Result<(), JwtError> {
        (|| -> anyhow::Result<()> {
            let message_digest = match self.algorithm.hash_algorithm {
                HashAlgorithm::SHA256 => MessageDigest::sha256(),
                HashAlgorithm::SHA384 => MessageDigest::sha384(),
                HashAlgorithm::SHA512 => MessageDigest::sha512()
            };
            
            let mut signer = openssl::sign::Signer::new(message_digest, &self.private_key)?;
            for part in data {
                signer.update(part)?;
            }
            let new_signature = signer.sign_to_vec()?;
            if !memcmp::eq(&new_signature, &signature) {
                bail!("Failed to verify.")
            }
            Ok(())
        })().map_err(|err| {
            JwtError::InvalidSignature(err)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Result;

    #[test]
    fn sign_and_verify() -> Result<()> {
        let private_key = b"ABCDE12345";
        let data = b"abcde12345";

        for hash in &[
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA512
        ] {
            let alg = HmacAlgorithm::new(*hash);

            let signer = alg.signer_from_bytes(private_key)?;
            let signature = signer.sign(&[data])?;
            signer.verify(&[data], &signature)?;
        }
        
        Ok(())
    }
}
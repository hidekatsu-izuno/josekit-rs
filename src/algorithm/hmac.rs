use openssl::pkey::{ PKey, Private };
use openssl::hash::MessageDigest;
use openssl::memcmp;
use anyhow::{ anyhow, bail };

use crate::error::JwtError;
use crate::algorithm::{ HashAlgorithm, Algorithm, Signer, Verifier };

pub struct HmacAlgorithm {
    hash_algorithm: HashAlgorithm
}

impl HmacAlgorithm {
    pub const fn new(hash_algorithm: HashAlgorithm) -> Self {
        HmacAlgorithm {
            hash_algorithm
        }
    }

    pub fn signer_from_bytes<'a>(&'a self, data: &[u8]) -> Result<impl Signer + Verifier + 'a, JwtError> {
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

impl<'a> Signer for HmacSigner<'a> {
    fn sign(&self, target: &[u8]) -> Result<Vec<u8>, JwtError> {
        let message_digest = match self.algorithm.hash_algorithm {
            HashAlgorithm::SHA256 => MessageDigest::sha256(),
            HashAlgorithm::SHA384 => MessageDigest::sha384(),
            HashAlgorithm::SHA512 => MessageDigest::sha512()
        };

        openssl::sign::Signer::new(message_digest, &self.private_key)
            .and_then(|mut signer| {
                signer.update(target)
                    .map(|_| signer)
            })
            .and_then(|signer| {
                signer.sign_to_vec()
            })
            .map_err(|err| {
                JwtError::InvalidSignature(anyhow!(err))
            })
    }
}

impl<'a> Verifier for HmacSigner<'a> {
    fn verify(&self, target: &[u8], signature: &[u8]) -> Result<(), JwtError> {
        let message_digest = match self.algorithm.hash_algorithm {
            HashAlgorithm::SHA256 => MessageDigest::sha256(),
            HashAlgorithm::SHA384 => MessageDigest::sha384(),
            HashAlgorithm::SHA512 => MessageDigest::sha512()
        };

        openssl::sign::Signer::new(message_digest, &self.private_key)
            .map_err(|err| anyhow!(err))
            .and_then(|mut signer| {
                signer.update(target)
                    .map_err(|err| anyhow!(err))
                    .map(|_| signer)
            })
            .and_then(|signer| {
                signer.sign_to_vec()
                    .map_err(|err| anyhow!(err))
            })
            .and_then(|vec| {
                if memcmp::eq(&vec, &signature) {
                    Ok(())
                } else {
                    bail!("Fail to verify.")
                }
            })
            .map_err(|err| {
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
        let target = b"abcde12345";

        for hash in &[
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA512
        ] {
            let alg = HmacAlgorithm::new(*hash);

            let signer = alg.signer_from_bytes(private_key)?;
            let signature = signer.sign(target)?;
            signer.verify(target, &signature)?;
        }
        
        Ok(())
    }
}
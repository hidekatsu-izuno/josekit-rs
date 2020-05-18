use openssl::pkey::{ PKey, Private, Public, HasPublic };
use openssl::rsa::Rsa;
use openssl::hash::MessageDigest;
use anyhow::{ anyhow, bail };

use crate::error::JwtError;
use crate::algorithm::{ HashAlgorithm, Algorithm, Signer, Verifier };

pub struct RsaAlgorithm {
    hash_algorithm: HashAlgorithm
}

impl RsaAlgorithm {
    pub const fn new(hash_algorithm: HashAlgorithm) -> Self {
        RsaAlgorithm {
            hash_algorithm
        }
    }

    pub fn signer_from_private_der<'a>(&'a self, data: &[u8]) -> Result<impl Signer<RsaAlgorithm> + 'a, JwtError> {
        PKey::private_key_from_der(&data)
            .or_else(|err| {
                Rsa::private_key_from_der(&data)
                    .and_then(|val| PKey::from_rsa(val))
                    .map_err(|_| anyhow!(err))
            })
            .and_then(Self::check_key)
            .map_err(|err| {
                JwtError::InvalidKeyFormat(err)
            })
            .map(|val| RsaSigner {
                algorithm: &self,
                private_key: val
            })
    }

    pub fn signer_from_private_pem<'a>(&'a self, data: &[u8]) -> Result<impl Signer<RsaAlgorithm> + 'a, JwtError> {
        PKey::private_key_from_pem(&data)
            .or_else(|err| {
                Rsa::private_key_from_pem(&data)
                    .and_then(|val| PKey::from_rsa(val))
                    .map_err(|_| anyhow!(err))
            })
            .and_then(Self::check_key)
            .map_err(|err| {
                JwtError::InvalidKeyFormat(err)
            })
            .map(|val| RsaSigner {
                algorithm: &self,
                private_key: val
            })
    }

    pub fn verifier_from_public_der<'a>(&'a self, data: &[u8]) -> Result<impl Verifier<RsaAlgorithm> + 'a, JwtError> {
        PKey::public_key_from_der(&data)
            .map_err(|err| anyhow!(err))
            .and_then(Self::check_key)
            .map_err(|err| {
                JwtError::InvalidKeyFormat(err)
            })
            .map(|val| RsaVerifier {
                algorithm: &self,
                public_key: val
            })
    }

    pub fn verifier_from_public_pem<'a>(&'a self, data: &[u8]) -> Result<impl Verifier<RsaAlgorithm> + 'a, JwtError> {
        PKey::public_key_from_pem(&data)
            .map_err(|err| anyhow!(err))
            .and_then(Self::check_key)
            .map_err(|err| {
                JwtError::InvalidKeyFormat(err)
            })
            .map(|val| RsaVerifier {
                algorithm: &self,
                public_key: val
            })
    }

    fn check_key<T>(pkey: PKey<T>) -> anyhow::Result<PKey<T>>
        where T: HasPublic
    {
        let rsa = pkey.rsa()?;

        if rsa.size() * 8 < 2048 {
            bail!("key length must be 2048 or more.");
        }

        Ok(pkey)
    }
}

impl Algorithm for RsaAlgorithm {
    fn name(&self) -> &str {
        match self.hash_algorithm {
            HashAlgorithm::SHA256 => "RS256",
            HashAlgorithm::SHA384 => "RS384",
            HashAlgorithm::SHA512 => "RS512",
        }
    }
}

pub struct RsaSigner<'a> {
    algorithm: &'a RsaAlgorithm,
    private_key: PKey<Private>
}

impl<'a> Signer<RsaAlgorithm> for RsaSigner<'a> {
    fn algorithm(&self) -> &RsaAlgorithm {
        &self.algorithm
    }

    fn sign(&self, data: &[&[u8]]) -> Result<Vec<u8>, JwtError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let message_digest = match self.algorithm.hash_algorithm {
                HashAlgorithm::SHA256 => MessageDigest::sha256(),
                HashAlgorithm::SHA384 => MessageDigest::sha384(),
                HashAlgorithm::SHA512 => MessageDigest::sha512(),
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

pub struct RsaVerifier<'a> {
    algorithm: &'a RsaAlgorithm,
    public_key: PKey<Public>
}

impl<'a> Verifier<RsaAlgorithm> for RsaVerifier<'a> {
    fn algorithm(&self) -> &RsaAlgorithm {
        &self.algorithm
    }

    fn verify(&self, data: &[&[u8]], signature: &[u8]) -> Result<(), JwtError> {
        (|| -> anyhow::Result<()> {
            let message_digest = match self.algorithm.hash_algorithm {
                HashAlgorithm::SHA256 => MessageDigest::sha256(),
                HashAlgorithm::SHA384 => MessageDigest::sha384(),
                HashAlgorithm::SHA512 => MessageDigest::sha512(),
            };
            
            let mut verifier = openssl::sign::Verifier::new(message_digest, &self.public_key)?;
            for part in data {
                verifier.update(part)?;
            }
            verifier.verify(signature)?;
            Ok(())
        })().map_err(|err| {
            JwtError::InvalidSignature(err)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;
    use anyhow::Result;
    
    #[test]
    fn load_private_pem() -> Result<()> {
        let key = load_file("keys/rsa_2048_private.pem")?;
        let _ = RsaAlgorithm::new(HashAlgorithm::SHA256).signer_from_private_pem(&key)?;
        Ok(())
    }
        
    #[test]
    fn load_private_pk1_pem() -> Result<()> {
        let key = load_file("keys/rsa_2048_pk1_private.pem")?;
        let _ = RsaAlgorithm::new(HashAlgorithm::SHA256).signer_from_private_pem(&key)?;
        Ok(())
    }

    #[test]
    fn load_public_pem() -> Result<()> {
        let key = load_file("keys/rsa_2048_public.pem")?;
        let _ = RsaAlgorithm::new(HashAlgorithm::SHA256).verifier_from_public_pem(&key)?;
        Ok(())
    }

    #[test]
    fn load_private_der() -> Result<()> {
        let key = load_file("keys/rsa_2048_private.der")?;
        let _ = RsaAlgorithm::new(HashAlgorithm::SHA256).signer_from_private_der(&key)?;
        Ok(())
    }
    
    #[test]
    fn load_private_pk1_der() -> Result<()> {
        let key = load_file("keys/rsa_2048_pk1_private.der")?;
        let _ = RsaAlgorithm::new(HashAlgorithm::SHA256).signer_from_private_der(&key)?;
        Ok(())
    }

    #[test]
    fn load_public_der() -> Result<()> {
        let key = load_file("keys/rsa_2048_public.der")?;
        let _ = RsaAlgorithm::new(HashAlgorithm::SHA256).verifier_from_public_der(&key)?;
        Ok(())
    }

    #[test]
    fn sign_and_verify_pem() -> Result<()> {
        let private_key = load_file("keys/rsa_2048_private.pem")?;
        let public_key = load_file("keys/rsa_2048_public.pem")?;
        let data = b"abcde12345";

        for hash in &[
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA512
        ] {
            let alg = RsaAlgorithm::new(*hash);

            let signer = alg.signer_from_private_pem(&private_key)?;
            let signature = signer.sign(&[data])?;

            let verifier = alg.verifier_from_public_pem(&public_key)?;
            verifier.verify(&[data], &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_der() -> Result<()> {
        let private_key = load_file("keys/rsa_2048_private.der")?;
        let public_key = load_file("keys/rsa_2048_public.der")?;
        let data = b"abcde12345";

        for hash in &[
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA512
        ] {
            let alg = RsaAlgorithm::new(*hash);

            let signer = alg.signer_from_private_der(&private_key)?;
            let signature = signer.sign(&[data])?;

            let verifier = alg.verifier_from_public_der(&public_key)?;
            verifier.verify(&[data], &signature)?;
        }
        
        Ok(())
    }

    fn load_file(path: &str) -> Result<Vec<u8>> {
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push("data");
        pb.push(path);

        let mut file = File::open(&pb)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(data)
    }
}

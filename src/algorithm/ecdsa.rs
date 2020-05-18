use openssl::pkey::{ PKey, Private, Public, HasPublic };
use openssl::ec::EcKey;
use openssl::nid::Nid;
use openssl::hash::MessageDigest;
use anyhow::{ anyhow, bail };

use crate::algorithm::{ HashAlgorithm, Algorithm, Signer, Verifier };
use crate::error::JwtError;

pub struct EcdsaAlgorithm {
    hash_algorithm: HashAlgorithm
}

impl EcdsaAlgorithm {
    pub const fn new(hash_algorithm: HashAlgorithm) -> Self {
        EcdsaAlgorithm {
            hash_algorithm
        }
    }

    pub fn signer_from_private_der<'a>(&'a self, data: &[u8]) -> Result<impl Signer<EcdsaAlgorithm> + 'a, JwtError> {
        PKey::private_key_from_der(&data)
            .or_else(|err| {
                EcKey::private_key_from_der(&data)
                    .and_then(|val| PKey::from_ec_key(val))
                    .map_err(|_| anyhow!(err))
            })
            .and_then(Self::check_key)
            .map_err(|err| {
                JwtError::InvalidKeyFormat(err)
            })
            .map(|val| {
                EcdsaSigner {
                    algorithm: &self,
                    private_key: val
                }
            })
    }

    pub fn signer_from_private_pem<'a>(&'a self, data: &[u8]) -> Result<impl Signer<EcdsaAlgorithm> + 'a, JwtError> {
        PKey::private_key_from_pem(&data)
            .or_else(|err| {
                EcKey::private_key_from_pem(&data)
                    .and_then(|val| PKey::from_ec_key(val))
                    .map_err(|_| anyhow!(err))
            })
            .and_then(Self::check_key)
            .map_err(|err| {
                JwtError::InvalidKeyFormat(err)
            })
            .map(|val| {
                EcdsaSigner {
                    algorithm: &self,
                    private_key: val
                }
            })
    }

    pub fn verifier_from_public_der<'a>(&'a self, data: &[u8]) -> Result<impl Verifier<EcdsaAlgorithm> + 'a, JwtError> {
        PKey::public_key_from_der(&data)
            .map_err(|err| anyhow!(err))
            .and_then(Self::check_key)
            .map_err(|err| {
                JwtError::InvalidKeyFormat(err)
            })
            .map(|val| {
                EcdsaVerifier {
                    algorithm: &self,
                    public_key: val
                }
            })
    }

    pub fn verifier_from_public_pem<'a>(&'a self, data: &[u8]) -> Result<impl Verifier<EcdsaAlgorithm> + 'a, JwtError> {
        PKey::public_key_from_pem(&data)
            .map_err(|err| anyhow!(err))
            .and_then(Self::check_key)
            .map_err(|err| {
                JwtError::InvalidKeyFormat(err)
            })
            .map(|val| {
                EcdsaVerifier {
                    algorithm: &self,
                    public_key: val
                }
            })
    }
    
    fn check_key<T>(pkey: PKey<T>) -> anyhow::Result<PKey<T>>
        where T: HasPublic
    {
        let ec_key = pkey.ec_key()?;

        let curve_name = ec_key.group().curve_name();
        if !matches!(curve_name, Some(Nid::X9_62_PRIME256V1)) {
            bail!("curve must be P-256: {:?}", curve_name);
        }

        Ok(pkey)
    }
}

impl Algorithm for EcdsaAlgorithm {
    fn name(&self) -> &str {
        match self.hash_algorithm {
            HashAlgorithm::SHA256 => "ES256",
            HashAlgorithm::SHA384 => "ES384",
            HashAlgorithm::SHA512 => "ES512",
        }
    }
}

pub struct EcdsaSigner<'a> {
    algorithm: &'a EcdsaAlgorithm,
    private_key: PKey<Private>
}

impl<'a> Signer<EcdsaAlgorithm> for EcdsaSigner<'a> {
    fn algorithm(&self) -> &EcdsaAlgorithm {
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

pub struct EcdsaVerifier<'a> {
    algorithm: &'a EcdsaAlgorithm,
    public_key: PKey<Public>
}

impl<'a> Verifier<EcdsaAlgorithm> for EcdsaVerifier<'a> {
    fn algorithm(&self) -> &EcdsaAlgorithm {
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
        let key = load_file("keys/ecdsa_p256_private.pem")?;
        let _ = EcdsaAlgorithm::new(HashAlgorithm::SHA256).signer_from_private_pem(&key)?;
        Ok(())
    }
        
    #[test]
    fn load_private_pk1_pem() -> Result<()> {
        let key = load_file("keys/ecdsa_p256_pk1_private.pem")?;
        let _ = EcdsaAlgorithm::new(HashAlgorithm::SHA256).signer_from_private_pem(&key)?;
        Ok(())
    }

    #[test]
    fn load_public_pem() -> Result<()> {
        let key = load_file("keys/ecdsa_p256_public.pem")?;
        let _ = EcdsaAlgorithm::new(HashAlgorithm::SHA256).verifier_from_public_pem(&key)?;
        Ok(())
    }

    #[test]
    fn load_private_der() -> Result<()> {
        let key = load_file("keys/ecdsa_p256_private.der")?;
        let _ = EcdsaAlgorithm::new(HashAlgorithm::SHA256).signer_from_private_der(&key)?;
        Ok(())
    }
    
    #[test]
    fn load_private_pk1_der() -> Result<()> {
        let key = load_file("keys/ecdsa_p256_pk1_private.der")?;
        let _ = EcdsaAlgorithm::new(HashAlgorithm::SHA256).signer_from_private_der(&key)?;
        Ok(())
    }

    #[test]
    fn load_public_der() -> Result<()> {
        let key = load_file("keys/ecdsa_p256_public.der")?;
        let _ = EcdsaAlgorithm::new(HashAlgorithm::SHA256).verifier_from_public_der(&key)?;
        Ok(())
    }

    #[test]
    fn sign_and_verify_pem() -> Result<()> {
        let private_key = load_file("keys/ecdsa_p256_private.pem")?;
        let public_key = load_file("keys/ecdsa_p256_public.pem")?;
        let data = b"abcde12345";

        for hash in &[
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA512
        ] {
            let alg = EcdsaAlgorithm::new(*hash);

            let signer = alg.signer_from_private_pem(&private_key)?;
            let signature = signer.sign(&[data])?;

            let verifier = alg.verifier_from_public_pem(&public_key)?;
            verifier.verify(&[data], &signature)?;
        }
        
        Ok(())
    }

    #[test]
    fn sign_and_verify_der() -> Result<()> {
        let private_key = load_file("keys/ecdsa_p256_private.der")?;
        let public_key = load_file("keys/ecdsa_p256_public.der")?;
        let data = b"abcde12345";

        for hash in &[
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA512
        ] {
            let alg = EcdsaAlgorithm::new(*hash);

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

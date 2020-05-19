use anyhow::{anyhow, bail};
use openssl::hash::MessageDigest;
use openssl::pkey::{HasPublic, PKey, Private, Public};

use crate::algorithm::{Algorithm, HashAlgorithm, Signer, Verifier};
use crate::error::JwtError;

#[derive(Debug, Eq, PartialEq)]
pub struct RsaPssAlgorithm {
    hash_algorithm: HashAlgorithm,
}

impl RsaPssAlgorithm {
    /// Return a new instance.
    ///
    /// # Arguments
    /// * `hash_algorithm` - A hash algorithm for digesting messege.
    pub const fn new(hash_algorithm: HashAlgorithm) -> Self {
        RsaPssAlgorithm { hash_algorithm }
    }

    /// Return a signer from a private key of PKCS#8 PEM format.
    ///
    /// # Arguments
    /// * `data` - A private key of PKCS#8 PEM format.
    pub fn signer_from_private_pem<'a>(
        &'a self,
        data: &[u8],
    ) -> Result<impl Signer<RsaPssAlgorithm> + 'a, JwtError> {
        PKey::private_key_from_pem(&data)
            .map_err(|err| anyhow!(err))
            .and_then(|pkey| (&self).check_key(pkey))
            .map_err(|err| JwtError::InvalidKeyFormat(err))
            .map(|val| RsaPssSigner {
                algorithm: &self,
                private_key: val,
            })
    }

    /// Return a signer from a private key of PKCS#8 DER format.
    ///
    /// # Arguments
    /// * `data` - A private key of PKCS#8 DER format.
    pub fn signer_from_private_der<'a>(
        &'a self,
        data: &[u8],
    ) -> Result<impl Signer<RsaPssAlgorithm> + 'a, JwtError> {
        PKey::private_key_from_der(&data)
            .map_err(|err| anyhow!(err))
            .and_then(|pkey| (&self).check_key(pkey))
            .map_err(|err| JwtError::InvalidKeyFormat(err))
            .map(|val| RsaPssSigner {
                algorithm: &self,
                private_key: val,
            })
    }

    /// Return a verifier from a public key of PKCS#8 PEM format.
    ///
    /// # Arguments
    /// * `data` - A public key of PKCS#8 PEM format.
    pub fn verifier_from_public_pem<'a>(
        &'a self,
        data: &[u8],
    ) -> Result<impl Verifier<RsaPssAlgorithm> + 'a, JwtError> {
        PKey::public_key_from_pem(&data)
            .map_err(|err| anyhow!(err))
            .and_then(|pkey| (&self).check_key(pkey))
            .map_err(|err| JwtError::InvalidKeyFormat(err))
            .map(|val| RsaPssVerifier {
                algorithm: &self,
                public_key: val,
            })
    }

    /// Return a verifier from a public key of PKCS#8 DER format.
    ///
    /// # Arguments
    /// * `data` - A public key of PKCS#8 DER format.
    pub fn verifier_from_public_der<'a>(
        &'a self,
        data: &[u8],
    ) -> Result<impl Verifier<RsaPssAlgorithm> + 'a, JwtError> {
        PKey::public_key_from_der(&data)
            .map_err(|err| anyhow!(err))
            .and_then(|pkey| (&self).check_key(pkey))
            .map_err(|err| JwtError::InvalidKeyFormat(err))
            .map(|val| RsaPssVerifier {
                algorithm: &self,
                public_key: val,
            })
    }

    fn check_key<T>(&self, pkey: PKey<T>) -> anyhow::Result<PKey<T>>
    where
        T: HasPublic,
    {
        let rsa = pkey.rsa()?;

        if rsa.size() * 8 < 2048 {
            bail!("key length must be 2048 or more.");
        }

        Ok(pkey)
    }
}

impl Algorithm for RsaPssAlgorithm {
    fn name(&self) -> &str {
        match self.hash_algorithm {
            HashAlgorithm::SHA256 => "PS256",
            HashAlgorithm::SHA384 => "PS384",
            HashAlgorithm::SHA512 => "PS512",
        }
    }
}

pub struct RsaPssSigner<'a> {
    algorithm: &'a RsaPssAlgorithm,
    private_key: PKey<Private>,
}

impl<'a> Signer<RsaPssAlgorithm> for RsaPssSigner<'a> {
    fn algorithm(&self) -> &RsaPssAlgorithm {
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
        })()
        .map_err(|err| JwtError::InvalidSignature(err))
    }
}

pub struct RsaPssVerifier<'a> {
    algorithm: &'a RsaPssAlgorithm,
    public_key: PKey<Public>,
}

impl<'a> Verifier<RsaPssAlgorithm> for RsaPssVerifier<'a> {
    fn algorithm(&self) -> &RsaPssAlgorithm {
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
        })()
        .map_err(|err| JwtError::InvalidSignature(err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Result;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;

    #[test]
    fn load_private_pem() -> Result<()> {
        for hash in &[
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA512,
        ] {
            let hash_name = hash_name(*hash);
            let key = load_file(&format!("keys/rsapss_2048_{}_private.pem", hash_name))?;
            let _ = RsaPssAlgorithm::new(HashAlgorithm::SHA256).signer_from_private_pem(&key)?;
        }
        Ok(())
    }

    #[test]
    fn load_private_der() -> Result<()> {
        for hash in &[
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA512,
        ] {
            let hash_name = hash_name(*hash);
            let key = load_file(&format!("keys/rsapss_2048_{}_private.der", hash_name))?;
            let _ = RsaPssAlgorithm::new(HashAlgorithm::SHA256).signer_from_private_der(&key)?;
        }
        Ok(())
    }

    #[test]
    fn load_public_pem() -> Result<()> {
        for hash in &[
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA512,
        ] {
            let hash_name = hash_name(*hash);
            let key = load_file(&format!("keys/rsapss_2048_{}_public.pem", hash_name))?;
            let _ = RsaPssAlgorithm::new(HashAlgorithm::SHA256).verifier_from_public_pem(&key)?;
        }
        Ok(())
    }

    #[test]
    fn load_public_der() -> Result<()> {
        for hash in &[
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA512,
        ] {
            let hash_name = hash_name(*hash);
            let key = load_file(&format!("keys/rsapss_2048_{}_public.der", hash_name))?;
            let _ = RsaPssAlgorithm::new(HashAlgorithm::SHA256).verifier_from_public_der(&key)?;
        }
        Ok(())
    }

    #[test]
    fn sign_and_verify_pem() -> Result<()> {
        let data = b"abcde12345";

        for hash in &[
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA512,
        ] {
            let hash_name = hash_name(*hash);
            let private_key = load_file(&format!("keys/rsapss_2048_{}_private.pem", hash_name))?;
            let public_key = load_file(&format!("keys/rsapss_2048_{}_public.pem", hash_name))?;

            let alg = RsaPssAlgorithm::new(*hash);

            let signer = alg.signer_from_private_pem(&private_key)?;
            let signature = signer.sign(&[data])?;

            let verifier = alg.verifier_from_public_pem(&public_key)?;
            verifier.verify(&[data], &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_der() -> Result<()> {
        let data = b"abcde12345";

        for hash in &[
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA512,
        ] {
            let hash_name = hash_name(*hash);
            let private_key = load_file(&format!("keys/rsapss_2048_{}_private.der", hash_name))?;
            let public_key = load_file(&format!("keys/rsapss_2048_{}_public.der", hash_name))?;

            let alg = RsaPssAlgorithm::new(*hash);

            let signer = alg.signer_from_private_der(&private_key)?;
            let signature = signer.sign(&[data])?;

            let verifier = alg.verifier_from_public_der(&public_key)?;
            verifier.verify(&[data], &signature)?;
        }

        Ok(())
    }

    fn hash_name(hash_algorithm: HashAlgorithm) -> &'static str {
        match hash_algorithm {
            HashAlgorithm::SHA256 => "sha256",
            HashAlgorithm::SHA384 => "sha384",
            HashAlgorithm::SHA512 => "sha512",
        }
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

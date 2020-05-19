use anyhow::{anyhow, bail};
use openssl::ec::EcKey;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{HasPublic, PKey, Private, Public};

use crate::algorithm::{Algorithm, HashAlgorithm, Signer, Verifier};
use crate::error::JwtError;

#[derive(Debug, Eq, PartialEq)]
pub struct EcdsaAlgorithm {
    hash_algorithm: HashAlgorithm,
}

impl EcdsaAlgorithm {
    /// Return a new instance.
    ///
    /// # Arguments
    /// * `hash_algorithm` - A hash algorithm for digesting messege.
    pub const fn new(hash_algorithm: HashAlgorithm) -> Self {
        EcdsaAlgorithm { hash_algorithm }
    }

    /// Return a signer from a private key of PKCS#1 or PKCS#8 PEM format.
    ///
    /// # Arguments
    /// * `data` - A private key of PKCS#1 or PKCS#8 PEM format.
    pub fn signer_from_private_pem<'a>(
        &'a self,
        data: &[u8],
    ) -> Result<impl Signer<EcdsaAlgorithm> + 'a, JwtError> {
        PKey::private_key_from_pem(&data)
            .or_else(|err| {
                EcKey::private_key_from_pem(&data)
                    .and_then(|val| PKey::from_ec_key(val))
                    .map_err(|_| anyhow!(err))
            })
            .and_then(|pkey| (&self).check_key(pkey))
            .map_err(|err| JwtError::InvalidKeyFormat(err))
            .map(|val| EcdsaSigner {
                algorithm: &self,
                private_key: val,
            })
    }

    /// Return a signer from a private key of PKCS#1 or PKCS#8 DER format.
    ///
    /// # Arguments
    /// * `data` - A private key of PKCS#1 or PKCS#8 DER format.
    pub fn signer_from_private_der<'a>(
        &'a self,
        data: &[u8],
    ) -> Result<impl Signer<EcdsaAlgorithm> + 'a, JwtError> {
        PKey::private_key_from_der(&data)
            .or_else(|err| {
                EcKey::private_key_from_der(&data)
                    .and_then(|val| PKey::from_ec_key(val))
                    .map_err(|_| anyhow!(err))
            })
            .and_then(|pkey| (&self).check_key(pkey))
            .map_err(|err| JwtError::InvalidKeyFormat(err))
            .map(|val| EcdsaSigner {
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
    ) -> Result<impl Verifier<EcdsaAlgorithm> + 'a, JwtError> {
        PKey::public_key_from_pem(&data)
            .map_err(|err| anyhow!(err))
            .and_then(|pkey| (&self).check_key(pkey))
            .map_err(|err| JwtError::InvalidKeyFormat(err))
            .map(|val| EcdsaVerifier {
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
    ) -> Result<impl Verifier<EcdsaAlgorithm> + 'a, JwtError> {
        PKey::public_key_from_der(&data)
            .map_err(|err| anyhow!(err))
            .and_then(|pkey| (&self).check_key(pkey))
            .map_err(|err| JwtError::InvalidKeyFormat(err))
            .map(|val| EcdsaVerifier {
                algorithm: &self,
                public_key: val,
            })
    }

    fn check_key<T>(&self, pkey: PKey<T>) -> anyhow::Result<PKey<T>>
    where
        T: HasPublic,
    {
        let ec_key = pkey.ec_key()?;

        let curve_name = match self.hash_algorithm {
            HashAlgorithm::SHA256 => Nid::X9_62_PRIME256V1,
            HashAlgorithm::SHA384 => Nid::SECP384R1,
            HashAlgorithm::SHA512 => Nid::SECP521R1,
        };

        match ec_key.group().curve_name() {
            Some(val) if val == curve_name => {}
            _ => bail!("Inappropriate curve: {:?}", curve_name),
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
    private_key: PKey<Private>,
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
        })()
        .map_err(|err| JwtError::InvalidSignature(err))
    }
}

pub struct EcdsaVerifier<'a> {
    algorithm: &'a EcdsaAlgorithm,
    public_key: PKey<Public>,
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
            let curve_name = curve_name(*hash);
            let key = load_file(&format!("keys/ecdsa_{}_private.pem", curve_name))?;
            let _ = EcdsaAlgorithm::new(*hash).signer_from_private_pem(&key)?;
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
            let curve_name = curve_name(*hash);
            let key = load_file(&format!("keys/ecdsa_{}_private.der", curve_name))?;
            let _ = EcdsaAlgorithm::new(*hash).signer_from_private_der(&key)?;
        }
        Ok(())
    }

    #[test]
    fn load_private_pk1_pem() -> Result<()> {
        for hash in &[
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA512,
        ] {
            let curve_name = curve_name(*hash);
            let key = load_file(&format!("keys/ecdsa_{}_pk1_private.pem", curve_name))?;
            let _ = EcdsaAlgorithm::new(*hash).signer_from_private_pem(&key)?;
        }
        Ok(())
    }

    #[test]
    fn load_private_pk1_der() -> Result<()> {
        for hash in &[
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA512,
        ] {
            let curve_name = curve_name(*hash);
            let key = load_file(&format!("keys/ecdsa_{}_pk1_private.der", curve_name))?;
            let _ = EcdsaAlgorithm::new(*hash).signer_from_private_der(&key)?;
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
            let curve_name = curve_name(*hash);
            let key = load_file(&format!("keys/ecdsa_{}_public.pem", curve_name))?;
            let _ = EcdsaAlgorithm::new(*hash).verifier_from_public_pem(&key)?;
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
            let curve_name = curve_name(*hash);
            let key = load_file(&format!("keys/ecdsa_{}_public.der", curve_name))?;
            let _ = EcdsaAlgorithm::new(*hash).verifier_from_public_der(&key)?;
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
            let curve_name = curve_name(*hash);

            let private_key = load_file(&format!("keys/ecdsa_{}_private.pem", curve_name))?;
            let public_key = load_file(&format!("keys/ecdsa_{}_public.pem", curve_name))?;

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
        let data = b"abcde12345";

        for hash in &[
            HashAlgorithm::SHA256,
            HashAlgorithm::SHA384,
            HashAlgorithm::SHA512,
        ] {
            let curve_name = curve_name(*hash);

            let private_key = load_file(&format!("keys/ecdsa_{}_private.der", curve_name))?;
            let public_key = load_file(&format!("keys/ecdsa_{}_public.der", curve_name))?;

            let alg = EcdsaAlgorithm::new(*hash);

            let signer = alg.signer_from_private_der(&private_key)?;
            let signature = signer.sign(&[data])?;

            let verifier = alg.verifier_from_public_der(&public_key)?;
            verifier.verify(&[data], &signature)?;
        }

        Ok(())
    }

    fn curve_name(hash_algorithm: HashAlgorithm) -> &'static str {
        match hash_algorithm {
            HashAlgorithm::SHA256 => "p256",
            HashAlgorithm::SHA384 => "p384",
            HashAlgorithm::SHA512 => "p521",
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

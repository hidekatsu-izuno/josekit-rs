use std::fmt::Display;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlgorithm {
    pub fn name(&self) -> &str {
        match self {
            Self::Sha1 => "SHA-1",
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
        }
    }

    pub fn output_len(&self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    #[cfg(all(
        feature = "openssl",
        not(feature = "aws-lc-rs"),
        not(all(
            feature = "aes-cbc-hmac-rustcrypto",
            feature = "ec-rustcrypto",
            feature = "hmac-rustcrypto",
            feature = "pbkdf2-rustcrypto",
            feature = "rsa-rustcrypto"
        ))
    ))]
    pub(crate) fn openssl(self) -> openssl::hash::MessageDigest {
        use openssl::hash::MessageDigest;

        match self {
            Self::Sha1 => MessageDigest::sha1(),
            Self::Sha256 => MessageDigest::sha256(),
            Self::Sha384 => MessageDigest::sha384(),
            Self::Sha512 => MessageDigest::sha512(),
        }
    }

    #[cfg(all(
        not(feature = "aws-lc-rs"),
        any(feature = "aes-cbc-hmac-rustcrypto", feature = "hmac-rustcrypto")
    ))]
    pub(crate) fn hmac(self, key: &[u8], parts: &[&[u8]]) -> anyhow::Result<Vec<u8>> {
        use hmac::{Hmac, KeyInit, Mac};
        use sha2::{Sha256, Sha384, Sha512};

        fn sign<D: hmac::EagerHash>(key: &[u8], parts: &[&[u8]]) -> anyhow::Result<Vec<u8>> {
            let mut mac = Hmac::<D>::new_from_slice(key)?;
            for part in parts {
                mac.update(part);
            }
            Ok(mac.finalize().into_bytes().to_vec())
        }

        match self {
            Self::Sha256 => sign::<Sha256>(key, parts),
            Self::Sha384 => sign::<Sha384>(key, parts),
            Self::Sha512 => sign::<Sha512>(key, parts),
            Self::Sha1 => anyhow::bail!("SHA-1 is unsupported for JOSE HMAC."),
        }
    }
}

impl Display for HashAlgorithm {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

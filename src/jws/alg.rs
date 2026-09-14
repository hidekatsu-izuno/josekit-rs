use anyhow::bail;
#[cfg(feature = "kapun-provider")]
use kapun_crypto_provider::{
    oid_registry::OID_PKCS1_SHA1WITHRSA, DecodingError, KapunCryptoProvider,
};

#[cfg(all(feature = "rsa-sha1", feature = "kapun-provider"))]
use crate::jws::alg::rsassa::RsassaJwsAlgorithm::Rs1;
use crate::{
    jwk::{Jwk, KeyPair},
    jws::{JwsSigner, JwsVerifier},
};

pub mod ecdsa;
pub mod eddsa;
pub mod hmac;
#[cfg(feature = "kapun-provider")]
mod kapun;
#[cfg(feature = "pqc")]
pub mod ml_dsa;
pub mod rsassa;
pub mod rsassa_pss;

impl TryFrom<&[u8]> for Box<dyn JwsVerifier> {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let der = value.as_ref();
        for alg in [crate::jws::ES256, crate::jws::ES384, crate::jws::ES512] {
            let Ok(verifier) = alg.verifier_from_der(der) else {
                continue;
            };
            return Ok(Box::new(verifier));
        }
        for alg in [
            crate::jws::RS256,
            crate::jws::RS384,
            crate::jws::RS512,
            #[cfg(feature = "rsa-sha1")]
            crate::jws::RS1,
        ] {
            let Ok(verifier) = alg.verifier_from_der(der) else {
                continue;
            };
            return Ok(Box::new(verifier));
        }
        for alg in [crate::jws::PS256, crate::jws::PS384, crate::jws::PS512] {
            let Ok(verifier) = alg.verifier_from_der(der) else {
                continue;
            };
            return Ok(Box::new(verifier));
        }
        for alg in [crate::jws::EdDSA] {
            let Ok(verifier) = alg.verifier_from_der(der) else {
                continue;
            };
            return Ok(Box::new(verifier));
        }
        #[cfg(feature = "pqc")]
        for alg in [
            crate::jws::MlDSA44,
            crate::jws::MlDSA65,
            crate::jws::MlDSA87,
        ] {
            let Ok(verifier) = alg.verifier_from_der(der) else {
                continue;
            };
            return Ok(Box::new(verifier));
        }
        bail!("invalid algorithm")
    }
}

impl TryFrom<&[u8]> for Box<dyn JwsSigner> {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let der = value.as_ref();
        for alg in [crate::jws::ES256, crate::jws::ES384, crate::jws::ES512] {
            let Ok(signer) = alg.signer_from_der(der) else {
                continue;
            };
            return Ok(Box::new(signer));
        }
        for alg in [
            crate::jws::RS256,
            crate::jws::RS384,
            crate::jws::RS512,
            #[cfg(feature = "rsa-sha1")]
            crate::jws::RS1,
        ] {
            let Ok(signer) = alg.signer_from_der(der) else {
                continue;
            };
            return Ok(Box::new(signer));
        }
        for alg in [crate::jws::PS256, crate::jws::PS384, crate::jws::PS512] {
            let Ok(signer) = alg.signer_from_der(der) else {
                continue;
            };
            return Ok(Box::new(signer));
        }
        for alg in [crate::jws::EdDSA] {
            let Ok(signer) = alg.signer_from_der(der) else {
                continue;
            };
            return Ok(Box::new(signer));
        }
        #[cfg(feature = "pqc")]
        for alg in [
            crate::jws::MlDSA44,
            crate::jws::MlDSA65,
            crate::jws::MlDSA87,
        ] {
            let Ok(signer) = alg.signer_from_der(der) else {
                continue;
            };
            return Ok(Box::new(signer));
        }
        bail!("invalid algorithm")
    }
}

impl TryFrom<&str> for Box<dyn JwsVerifier> {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let jwk = Jwk::from_bytes(value.as_bytes())?;
        for alg in [crate::jws::ES256, crate::jws::ES384, crate::jws::ES512] {
            let Ok(verifier) = alg.verifier_from_jwk(&jwk) else {
                continue;
            };
            return Ok(Box::new(verifier));
        }
        for alg in [
            crate::jws::RS256,
            crate::jws::RS384,
            crate::jws::RS512,
            #[cfg(feature = "rsa-sha1")]
            crate::jws::RS1,
        ] {
            let Ok(verifier) = alg.verifier_from_jwk(&jwk) else {
                continue;
            };
            return Ok(Box::new(verifier));
        }
        for alg in [crate::jws::PS256, crate::jws::PS384, crate::jws::PS512] {
            let Ok(verifier) = alg.verifier_from_jwk(&jwk) else {
                continue;
            };
            return Ok(Box::new(verifier));
        }
        for alg in [crate::jws::EdDSA] {
            let Ok(verifier) = alg.verifier_from_jwk(&jwk) else {
                continue;
            };
            return Ok(Box::new(verifier));
        }
        #[cfg(feature = "pqc")]
        for alg in [
            crate::jws::MlDSA44,
            crate::jws::MlDSA65,
            crate::jws::MlDSA87,
        ] {
            let Ok(verifier) = alg.verifier_from_jwk(&jwk) else {
                continue;
            };
            return Ok(Box::new(verifier));
        }
        bail!("invalid algorithm")
    }
}

impl TryFrom<&str> for Box<dyn JwsSigner> {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let jwk = Jwk::from_bytes(value.as_bytes())?;
        for alg in [crate::jws::ES256, crate::jws::ES384, crate::jws::ES512] {
            let Ok(signer) = alg.signer_from_jwk(&jwk) else {
                continue;
            };
            return Ok(Box::new(signer));
        }
        for alg in [
            crate::jws::RS256,
            crate::jws::RS384,
            crate::jws::RS512,
            #[cfg(feature = "rsa-sha1")]
            crate::jws::RS1,
        ] {
            let Ok(signer) = alg.signer_from_jwk(&jwk) else {
                continue;
            };
            return Ok(Box::new(signer));
        }
        for alg in [crate::jws::PS256, crate::jws::PS384, crate::jws::PS512] {
            let Ok(signer) = alg.signer_from_jwk(&jwk) else {
                continue;
            };
            return Ok(Box::new(signer));
        }
        for alg in [crate::jws::EdDSA] {
            let Ok(signer) = alg.signer_from_jwk(&jwk) else {
                continue;
            };
            return Ok(Box::new(signer));
        }
        #[cfg(feature = "pqc")]
        for alg in [
            crate::jws::MlDSA44,
            crate::jws::MlDSA65,
            crate::jws::MlDSA87,
        ] {
            let Ok(signer) = alg.signer_from_jwk(&jwk) else {
                continue;
            };
            return Ok(Box::new(signer));
        }
        bail!("invalid algorithm")
    }
}

impl TryFrom<&[u8]> for Box<dyn KeyPair> {
    type Error = anyhow::Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let der = value.as_ref();
        for alg in [crate::jws::ES256, crate::jws::ES384, crate::jws::ES512] {
            let Ok(key_pair) = alg.key_pair_from_der(der) else {
                continue;
            };
            return Ok(Box::new(key_pair));
        }

        for alg in [
            crate::jws::RS256,
            crate::jws::RS384,
            crate::jws::RS512,
            #[cfg(feature = "rsa-sha1")]
            crate::jws::RS1,
        ] {
            let Ok(key_pair) = alg.key_pair_from_der(der) else {
                continue;
            };
            return Ok(Box::new(key_pair));
        }
        for alg in [crate::jws::PS256, crate::jws::PS384, crate::jws::PS512] {
            let Ok(key_pair) = alg.key_pair_from_der(der) else {
                continue;
            };
            return Ok(Box::new(key_pair));
        }
        for alg in [crate::jws::EdDSA] {
            let Ok(key_pair) = alg.key_pair_from_der(der) else {
                continue;
            };
            return Ok(Box::new(key_pair));
        }
        #[cfg(feature = "pqc")]
        for alg in [
            crate::jws::MlDSA44,
            crate::jws::MlDSA65,
            crate::jws::MlDSA87,
        ] {
            let Ok(key_pair) = alg.key_pair_from_der(der) else {
                continue;
            };
            return Ok(Box::new(key_pair));
        }
        bail!("invalid algorithm")
    }
}

pub struct JosekitCryptoProvider;
#[cfg(feature = "kapun-provider")]
impl KapunCryptoProvider for JosekitCryptoProvider {
    fn verifier(
        key_data: Vec<u8>,
    ) -> Result<Box<dyn kapun_crypto_provider::Verifier>, DecodingError> {
        let jws_verifier: Box<dyn JwsVerifier> = key_data
            .as_slice()
            .try_into()
            .map_err(|_| DecodingError::InvalidAlgorithm)?;
        Ok(jws_verifier)
    }
    fn verifier_for_oid<'a>(
        key_data: Vec<u8>,
        oid: kapun_crypto_provider::oid_registry::Oid<'a>,
    ) -> Result<Box<dyn kapun_crypto_provider::Verifier + 'a>, DecodingError> {
        if oid == OID_PKCS1_SHA1WITHRSA {
            #[cfg(feature = "rsa-sha1")]
            {
                return Ok(Box::new(
                    Rs1.verifier_from_der(key_data)
                        .map_err(|_| DecodingError::InvalidAlgorithm)?,
                ));
            }
            #[cfg(not(feature = "rsa-sha1"))]
            Err(DecodingError::InvalidAlgorithm)
        } else {
            Self::verifier(key_data)
        }
    }

    fn signer(key_data: Vec<u8>) -> Result<Box<dyn kapun_crypto_provider::Signer>, DecodingError> {
        let jws_signer: Box<dyn JwsSigner> = key_data
            .as_slice()
            .try_into()
            .map_err(|_| DecodingError::InvalidAlgorithm)?;
        Ok(jws_signer)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        jwk::KeyPair,
        jws::{alg::ecdsa::EcdsaJwsAlgorithm::Es256, JwsSigner, JwsVerifier},
    };

    #[test]
    fn test_from() {
        let k = Es256.generate_key_pair().unwrap();
        let pk = k.to_der_public_key();
        let sk = k.into_private_key().ec_key_der().unwrap();

        let signer: Box<dyn JwsSigner> = sk.as_slice().try_into().unwrap();
        let verifier: Box<dyn JwsVerifier> = pk.as_slice().try_into().unwrap();

        let sig = signer.sign(b"test").unwrap();
        verifier.verify(b"test", &sig).unwrap();

        let kp: Box<dyn KeyPair> = sk.as_slice().try_into().unwrap();
        assert_eq!(kp.algorithm(), Some("ES256"));
        assert_eq!(kp.to_der_public_key(), pk);
    }
}

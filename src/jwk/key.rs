use anyhow::bail;
#[cfg(feature = "x448-goldilocks-plus")]
use ed448_goldilocks_plus::{
    subtle::ConstantTimeEq,
    x448::{PublicKey as X448PublicKey, StaticSecret as X448Secret, X448_LENGTH},
};
#[cfg(feature = "ed448-goldilocks-plus")]
use ed448_goldilocks_plus::{Signature, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
#[cfg(all(feature = "hmac-rustcrypto", not(feature = "aws-lc-rs")))]
use hmac::digest::zeroize::Zeroize;
#[cfg(all(
    feature = "openssl",
    not(all(
        any(feature = "ec-rustcrypto", feature = "aws-lc-rs"),
        feature = "x25519-dalek",
        feature = "x448-goldilocks-plus"
    ))
))]
use openssl::derive::Deriver;
#[cfg(any(
    not(any(feature = "ec-rustcrypto", feature = "aws-lc-rs")),
    not(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))
))]
use openssl::hash::MessageDigest;
#[cfg(any(
    not(any(feature = "ec-rustcrypto", feature = "aws-lc-rs")),
    not(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))
))]
use openssl::pkey::PKeyRef;
#[cfg(all(
    feature = "openssl",
    not(all(
        any(feature = "ec-rustcrypto", feature = "aws-lc-rs"),
        any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"),
        feature = "ed25519-dalek",
        feature = "ed448-goldilocks-plus",
        feature = "x25519-dalek",
        feature = "x448-goldilocks-plus",
    ))
))]
use openssl::pkey::Public;
#[cfg(feature = "openssl")]
use openssl::pkey::{PKey, Private};
#[cfg(all(
    feature = "openssl",
    not(feature = "aws-lc-rs"),
    not(all(
        feature = "aes-cbc-hmac-rustcrypto",
        any(feature = "ec-rustcrypto", feature = "aws-lc-rs"),
        feature = "ed25519-dalek",
        feature = "ed448-goldilocks-plus",
        feature = "hmac-rustcrypto",
        any(feature = "rsa-rustcrypto", feature = "aws-lc-rs")
    ))
))]
use openssl::sign::Signer;
#[cfg(all(
    feature = "openssl",
    not(all(
        any(feature = "ec-rustcrypto", feature = "aws-lc-rs"),
        feature = "ed25519-dalek",
        feature = "ed448-goldilocks-plus",
        any(feature = "rsa-rustcrypto", feature = "aws-lc-rs")
    ))
))]
use openssl::sign::Verifier;
#[cfg(not(any(feature = "ec-rustcrypto", feature = "aws-lc-rs")))]
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
};
#[cfg(not(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs")))]
use openssl::{
    encrypt::{Decrypter, Encrypter},
    rsa::Rsa,
};
#[cfg(feature = "aws-lc-rs")]
use pkcs8::der::zeroize::Zeroize;

#[cfg(any(
    feature = "ed25519-dalek",
    feature = "ed448-goldilocks-plus",
    feature = "x25519-dalek",
    feature = "x448-goldilocks-plus"
))]
use crate::jwk::alg::okp;
use crate::jwk::alg::{ec::EcCurve, ecx::EcxCurve, ed::EdCurve};
use crate::util::der::{DerBuilder, DerType};
use crate::util::oid::ObjectIdentifier;
#[cfg(feature = "ed448-goldilocks-plus")]
use crate::util::oid::OID_ED448;
#[cfg(feature = "x448-goldilocks-plus")]
use crate::util::oid::OID_X448;
use crate::util::HashAlgorithm;

#[cfg(feature = "ed25519-dalek")]
use crate::util::oid::OID_ED25519;
#[cfg(feature = "x25519-dalek")]
use crate::util::oid::OID_X25519;
#[cfg(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))]
use crate::util::oid::{OID_RSASSA_PSS, OID_RSA_ENCRYPTION};

#[cfg(all(feature = "ec-rustcrypto", not(feature = "aws-lc-rs")))]
mod ec;
#[cfg(feature = "aws-lc-rs")]
#[path = "key/ec_aws_lc.rs"]
mod ec;

#[cfg(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))]
#[path = "key/rsa.rs"]
mod rsa_rustcrypto;
#[cfg(all(feature = "rsa-rustcrypto", not(feature = "aws-lc-rs")))]
use rsa_rustcrypto as rsa_backend;
#[cfg(feature = "aws-lc-rs")]
#[path = "key/rsa_aws_lc.rs"]
mod rsa_backend;

#[derive(Debug, Clone)]
pub(crate) enum PrivateKey {
    #[cfg(feature = "openssl")]
    OpenSsl(PKey<Private>),
    #[cfg(any(feature = "ec-rustcrypto", feature = "aws-lc-rs"))]
    Ec(Box<ec::EcPrivateKey>),
    #[cfg(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))]
    Rsa(Box<rsa_backend::Private>),
    #[cfg(any(feature = "hmac-rustcrypto", feature = "aws-lc-rs"))]
    Hmac(HmacKey),
    #[cfg(feature = "ed25519-dalek")]
    Ed25519(Box<ed25519_dalek::SigningKey>),
    #[cfg(feature = "x25519-dalek")]
    X25519(X25519Secret),
    #[cfg(feature = "ed448-goldilocks-plus")]
    Ed448(Box<SigningKey>),
    #[cfg(feature = "x448-goldilocks-plus")]
    X448(X448Secret),
}

#[cfg(any(feature = "hmac-rustcrypto", feature = "aws-lc-rs"))]
#[derive(Clone)]
pub(crate) struct HmacKey(Box<[u8]>);

#[cfg(any(feature = "hmac-rustcrypto", feature = "aws-lc-rs"))]
impl Drop for HmacKey {
    fn drop(&mut self) {
        self.0.as_mut().zeroize();
    }
}

#[cfg(any(feature = "hmac-rustcrypto", feature = "aws-lc-rs"))]
impl std::fmt::Debug for HmacKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacKey").finish_non_exhaustive()
    }
}

#[cfg(feature = "x25519-dalek")]
#[derive(Clone)]
pub(crate) struct X25519Secret(x25519_dalek::StaticSecret);

#[cfg(feature = "x25519-dalek")]
impl std::fmt::Debug for X25519Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519Secret").finish_non_exhaustive()
    }
}

impl PrivateKey {
    pub(crate) fn generate_rsa(bits: u32) -> anyhow::Result<Self> {
        #[cfg(not(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs")))]
        return Ok(Self::OpenSsl(PKey::from_rsa(Rsa::generate(bits)?)?));
        #[cfg(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))]
        Ok(Self::Rsa(Box::new(rsa_backend::generate(bits as usize)?)))
    }

    pub(crate) fn generate_ec(curve: EcCurve) -> anyhow::Result<Self> {
        #[cfg(not(any(feature = "ec-rustcrypto", feature = "aws-lc-rs")))]
        {
            let nid = match curve {
                EcCurve::P256 => Nid::X9_62_PRIME256V1,
                EcCurve::P384 => Nid::SECP384R1,
                EcCurve::P521 => Nid::SECP521R1,
                EcCurve::Secp256k1 => Nid::SECP256K1,
            };
            let group = EcGroup::from_curve_name(nid)?;
            Ok(Self::OpenSsl(PKey::from_ec_key(EcKey::generate(&group)?)?))
        }
        #[cfg(any(feature = "ec-rustcrypto", feature = "aws-lc-rs"))]
        Ok(Self::Ec(Box::new(ec::EcPrivateKey::generate(curve)?)))
    }

    pub(crate) fn hmac(secret: &[u8]) -> anyhow::Result<Self> {
        #[cfg(not(any(feature = "hmac-rustcrypto", feature = "aws-lc-rs")))]
        return Ok(Self::OpenSsl(PKey::hmac(secret)?));
        #[cfg(any(feature = "hmac-rustcrypto", feature = "aws-lc-rs"))]
        Ok(Self::Hmac(HmacKey(secret.into())))
    }

    pub(crate) fn sign_hmac(
        &self,
        hash: HashAlgorithm,
        parts: &[&[u8]],
    ) -> anyhow::Result<Vec<u8>> {
        match self {
            #[cfg(not(any(feature = "hmac-rustcrypto", feature = "aws-lc-rs")))]
            Self::OpenSsl(key) => Self::sign_openssl_hmac(key, hash, parts),
            #[cfg(all(feature = "hmac-rustcrypto", not(feature = "aws-lc-rs")))]
            Self::Hmac(key) => hash.hmac(&key.0, parts),
            #[cfg(feature = "aws-lc-rs")]
            Self::Hmac(key) => crate::aws_lc::sign_hmac(hash, &key.0, parts),
            #[allow(unreachable_patterns)]
            _ => bail!("Incompatible HMAC key."),
        }
    }

    #[cfg(not(any(feature = "aes-cbc-hmac-rustcrypto", feature = "aws-lc-rs")))]
    pub(crate) fn openssl_hmac(
        secret: &[u8],
        hash: HashAlgorithm,
        parts: &[&[u8]],
    ) -> anyhow::Result<Vec<u8>> {
        Self::sign_openssl_hmac(&PKey::hmac(secret)?, hash, parts)
    }

    #[cfg(all(
        not(feature = "aws-lc-rs"),
        any(
            not(feature = "aes-cbc-hmac-rustcrypto"),
            not(feature = "hmac-rustcrypto")
        )
    ))]
    fn sign_openssl_hmac(
        key: &PKey<Private>,
        hash: HashAlgorithm,
        parts: &[&[u8]],
    ) -> anyhow::Result<Vec<u8>> {
        let mut signer = Signer::new(hash.openssl(), key)?;
        for part in parts {
            signer.update(part)?;
        }
        Ok(signer.sign_to_vec()?)
    }

    pub(crate) fn generate_ed(curve: EdCurve) -> anyhow::Result<Self> {
        match curve {
            #[cfg(not(feature = "ed25519-dalek"))]
            EdCurve::Ed25519 => Ok(Self::OpenSsl(PKey::generate_ed25519()?)),
            #[cfg(feature = "ed25519-dalek")]
            EdCurve::Ed25519 => {
                let seed = okp::random_secret::<32>()?;
                Ok(Self::Ed25519(Box::new(
                    ed25519_dalek::SigningKey::from_bytes(&seed),
                )))
            }
            #[cfg(not(feature = "ed448-goldilocks-plus"))]
            EdCurve::Ed448 => Ok(Self::OpenSsl(PKey::generate_ed448()?)),
            #[cfg(feature = "ed448-goldilocks-plus")]
            EdCurve::Ed448 => {
                let seed = okp::random_secret::<SECRET_KEY_LENGTH>()?;
                Self::from_ed448_bytes(seed.as_ref())
            }
        }
    }

    pub(crate) fn generate_ecx(curve: EcxCurve) -> anyhow::Result<Self> {
        match curve {
            #[cfg(not(feature = "x25519-dalek"))]
            EcxCurve::X25519 => Ok(Self::OpenSsl(PKey::generate_x25519()?)),
            #[cfg(feature = "x25519-dalek")]
            EcxCurve::X25519 => {
                let seed = okp::random_secret::<32>()?;
                Ok(Self::X25519(X25519Secret(
                    x25519_dalek::StaticSecret::from(*seed),
                )))
            }
            #[cfg(not(feature = "x448-goldilocks-plus"))]
            EcxCurve::X448 => Ok(Self::OpenSsl(PKey::generate_x448()?)),
            #[cfg(feature = "x448-goldilocks-plus")]
            EcxCurve::X448 => {
                let secret = okp::random_secret::<X448_LENGTH>()?;
                Ok(Self::X448(X448Secret::from(*secret)))
            }
        }
    }

    pub(crate) fn from_der(der: &[u8], oid: &ObjectIdentifier) -> anyhow::Result<Self> {
        #[cfg(any(feature = "ec-rustcrypto", feature = "aws-lc-rs"))]
        if let Some(curve) = EcCurve::from_oid(oid) {
            return Ok(Self::Ec(Box::new(ec::EcPrivateKey::from_der(der, curve)?)));
        }

        match oid {
            #[cfg(feature = "ed25519-dalek")]
            oid if oid == &*OID_ED25519 => {
                let bytes = okp::private_key_bytes(der, okp::ED25519_OID)?.try_into()?;
                Ok(Self::Ed25519(Box::new(
                    ed25519_dalek::SigningKey::from_bytes(bytes),
                )))
            }
            #[cfg(feature = "x25519-dalek")]
            oid if oid == &*OID_X25519 => {
                let bytes: [u8; 32] = okp::private_key_bytes(der, okp::X25519_OID)?.try_into()?;
                Ok(Self::X25519(X25519Secret(
                    x25519_dalek::StaticSecret::from(bytes),
                )))
            }
            #[cfg(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))]
            oid if oid == &*OID_RSA_ENCRYPTION || oid == &*OID_RSASSA_PSS => Ok(Self::Rsa(
                Box::new(rsa_backend::private_key_from_der(der, oid)?),
            )),
            #[cfg(feature = "ed448-goldilocks-plus")]
            oid if oid == &*OID_ED448 => {
                Self::from_ed448_bytes(okp::private_key_bytes(der, okp::ED448_OID)?)
            }
            #[cfg(feature = "x448-goldilocks-plus")]
            oid if oid == &*OID_X448 => {
                let bytes: [u8; X448_LENGTH] =
                    okp::private_key_bytes(der, okp::X448_OID)?.try_into()?;
                Ok(Self::X448(X448Secret::from(bytes)))
            }
            #[cfg(feature = "openssl")]
            _ => Ok(Self::OpenSsl(PKey::private_key_from_der(der)?)),
            #[cfg(not(feature = "openssl"))]
            _ => bail!("Unsupported private key algorithm identifier: {oid}"),
        }
    }

    #[cfg(feature = "ed448-goldilocks-plus")]
    fn from_ed448_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        let key = SigningKey::try_from(bytes).map_err(anyhow::Error::msg)?;
        Ok(Self::Ed448(Box::new(key)))
    }

    #[cfg(any(
        not(any(feature = "ec-rustcrypto", feature = "aws-lc-rs")),
        not(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))
    ))]
    fn as_openssl(&self) -> anyhow::Result<&PKeyRef<Private>> {
        match self {
            Self::OpenSsl(key) => Ok(key.as_ref()),
            #[allow(unreachable_patterns)]
            _ => bail!("This operation requires an OpenSSL private key."),
        }
    }

    pub(crate) fn rsa_size(&self) -> anyhow::Result<usize> {
        #[cfg(not(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs")))]
        return Ok(self.as_openssl()?.size());
        #[cfg(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))]
        Ok(rsa_backend::size(self.rsa()?))
    }

    #[cfg(not(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs")))]
    pub(crate) fn openssl_rsa(&self) -> anyhow::Result<Rsa<Private>> {
        Ok(self.as_openssl()?.rsa()?)
    }

    #[cfg(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))]
    fn rsa(&self) -> anyhow::Result<&rsa_backend::Private> {
        match self {
            Self::Rsa(key) => Ok(key),
            _ => bail!("Incompatible RSA private key."),
        }
    }

    #[cfg(not(any(feature = "ec-rustcrypto", feature = "aws-lc-rs")))]
    pub(crate) fn openssl_ec_key(&self) -> anyhow::Result<EcKey<Private>> {
        Ok(self.as_openssl()?.ec_key()?)
    }

    #[cfg(any(feature = "ec-rustcrypto", feature = "aws-lc-rs"))]
    fn ec(&self) -> &ec::EcPrivateKey {
        match self {
            Self::Ec(key) => key,
            _ => unreachable!("Expected an EC private key."),
        }
    }

    #[cfg(any(feature = "ec-rustcrypto", feature = "aws-lc-rs"))]
    pub(crate) fn ec_scalar(&self) -> Vec<u8> {
        self.ec().scalar()
    }

    #[cfg(any(feature = "ec-rustcrypto", feature = "aws-lc-rs"))]
    pub(crate) fn ec_coordinates(&self) -> (Vec<u8>, Vec<u8>) {
        self.ec().coordinates()
    }

    #[cfg(any(feature = "ec-rustcrypto", feature = "aws-lc-rs"))]
    pub(crate) fn sign_ecdsa(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        self.ec().sign(message)
    }

    #[cfg(any(
        not(any(feature = "ec-rustcrypto", feature = "aws-lc-rs")),
        not(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))
    ))]
    pub(crate) fn openssl_signer(&self, digest: MessageDigest) -> anyhow::Result<Signer<'_>> {
        Ok(Signer::new(digest, self.as_openssl()?)?)
    }

    #[cfg(not(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs")))]
    pub(crate) fn openssl_decrypter(&self) -> anyhow::Result<Decrypter<'_>> {
        Ok(Decrypter::new(self.as_openssl()?)?)
    }

    pub(crate) fn rsa_private_der(&self) -> Vec<u8> {
        #[cfg(not(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs")))]
        return self.openssl_rsa().unwrap().private_key_to_der().unwrap();
        #[cfg(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))]
        rsa_backend::export_private(self.rsa().unwrap()).unwrap()
    }

    pub(crate) fn rsa_public_der(&self) -> Vec<u8> {
        #[cfg(not(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs")))]
        return self
            .openssl_rsa()
            .unwrap()
            .public_key_to_der_pkcs1()
            .unwrap();
        #[cfg(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))]
        rsa_backend::export_public(&rsa_backend::to_public(self.rsa().unwrap()).unwrap()).unwrap()
    }

    #[cfg(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))]
    pub(crate) fn rsa_sign(
        &self,
        hash: HashAlgorithm,
        pss: bool,
        message: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        rsa_backend::sign(self.rsa()?, hash, pss, message)
    }

    #[cfg(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))]
    pub(crate) fn rsa_decrypt(
        &self,
        hash: Option<HashAlgorithm>,
        ciphertext: &[u8],
        key_len: usize,
    ) -> anyhow::Result<Vec<u8>> {
        rsa_backend::decrypt(self.rsa()?, hash, ciphertext, key_len)
    }

    pub(crate) fn to_der_private_key(&self) -> Vec<u8> {
        match self {
            #[cfg(feature = "openssl")]
            Self::OpenSsl(key) => key.private_key_to_der().unwrap(),
            #[cfg(any(feature = "ec-rustcrypto", feature = "aws-lc-rs"))]
            Self::Ec(key) => key.private_der(),
            #[cfg(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))]
            Self::Rsa(_) => self.rsa_private_der(),
            #[cfg(feature = "ed25519-dalek")]
            Self::Ed25519(key) => encode_okp_private_key(&OID_ED25519, key.as_bytes()),
            #[cfg(feature = "x25519-dalek")]
            Self::X25519(key) => encode_okp_private_key(&OID_X25519, key.0.as_bytes()),
            #[cfg(any(feature = "hmac-rustcrypto", feature = "aws-lc-rs"))]
            Self::Hmac(_) => unreachable!("HMAC secrets are not DER keys."),
            #[cfg(feature = "ed448-goldilocks-plus")]
            Self::Ed448(key) => encode_okp_private_key(&OID_ED448, key.as_bytes().as_slice()),
            #[cfg(feature = "x448-goldilocks-plus")]
            Self::X448(key) => encode_okp_private_key(&OID_X448, key.as_bytes()),
        }
    }

    pub(crate) fn to_der_public_key(&self) -> Vec<u8> {
        match self {
            #[cfg(feature = "openssl")]
            Self::OpenSsl(key) => key.public_key_to_der().unwrap(),
            #[cfg(any(feature = "ec-rustcrypto", feature = "aws-lc-rs"))]
            Self::Ec(key) => key.public_der(),
            #[cfg(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))]
            Self::Rsa(_) => {
                crate::jwk::alg::rsa::RsaKeyPair::to_pkcs8(&self.rsa_public_der(), true)
            }
            #[cfg(feature = "ed25519-dalek")]
            Self::Ed25519(key) => {
                encode_okp_public_key(&OID_ED25519, key.verifying_key().as_bytes())
            }
            #[cfg(feature = "x25519-dalek")]
            Self::X25519(key) => encode_okp_public_key(
                &OID_X25519,
                x25519_dalek::PublicKey::from(&key.0).as_bytes(),
            ),
            #[cfg(any(feature = "hmac-rustcrypto", feature = "aws-lc-rs"))]
            Self::Hmac(_) => unreachable!("HMAC secrets have no public keys."),
            #[cfg(feature = "ed448-goldilocks-plus")]
            Self::Ed448(key) => encode_okp_public_key(&OID_ED448, key.verifying_key().as_bytes()),
            #[cfg(feature = "x448-goldilocks-plus")]
            Self::X448(key) => {
                encode_okp_public_key(&OID_X448, X448PublicKey::from(key).as_bytes())
            }
        }
    }

    pub(crate) fn to_pem_private_key(&self) -> Vec<u8> {
        match self {
            #[cfg(feature = "openssl")]
            Self::OpenSsl(key) => key.private_key_to_pem_pkcs8().unwrap(),
            #[cfg(any(feature = "ec-rustcrypto", feature = "aws-lc-rs"))]
            Self::Ec(key) => crate::util::encode_pem("PRIVATE KEY", &key.pkcs8_der()),
            #[cfg(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))]
            Self::Rsa(_) => {
                let pkcs8 =
                    crate::jwk::alg::rsa::RsaKeyPair::to_pkcs8(&self.rsa_private_der(), false);
                crate::util::encode_pem("PRIVATE KEY", &pkcs8)
            }
            #[cfg(any(feature = "hmac-rustcrypto", feature = "aws-lc-rs"))]
            Self::Hmac(_) => unreachable!("HMAC secrets are not PEM keys."),
            #[cfg(any(
                feature = "ed25519-dalek",
                feature = "ed448-goldilocks-plus",
                feature = "x25519-dalek",
                feature = "x448-goldilocks-plus"
            ))]
            _ => crate::util::encode_pem("PRIVATE KEY", &self.to_der_private_key()),
        }
    }

    pub(crate) fn to_pem_public_key(&self) -> Vec<u8> {
        match self {
            #[cfg(feature = "openssl")]
            Self::OpenSsl(key) => key.public_key_to_pem().unwrap(),
            #[cfg(any(feature = "hmac-rustcrypto", feature = "aws-lc-rs"))]
            Self::Hmac(_) => unreachable!("HMAC secrets have no public keys."),
            #[cfg(any(
                feature = "ed25519-dalek",
                feature = "ed448-goldilocks-plus",
                feature = "x25519-dalek",
                feature = "x448-goldilocks-plus",
                any(feature = "ec-rustcrypto", feature = "aws-lc-rs"),
                any(feature = "rsa-rustcrypto", feature = "aws-lc-rs")
            ))]
            _ => crate::util::encode_pem("PUBLIC KEY", &self.to_der_public_key()),
        }
    }

    pub(crate) fn sign_eddsa(&self, message: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self {
            #[cfg(all(
                feature = "openssl",
                not(all(feature = "ed25519-dalek", feature = "ed448-goldilocks-plus"))
            ))]
            Self::OpenSsl(key) => {
                let mut signer = Signer::new_without_digest(key)?;
                let mut signature = vec![0; signer.len()?];
                signer.sign_oneshot(&mut signature, message)?;
                Ok(signature)
            }
            #[cfg(feature = "ed448-goldilocks-plus")]
            Self::Ed448(key) => Ok(key.sign_raw(message).to_bytes().to_vec()),
            #[cfg(feature = "ed25519-dalek")]
            Self::Ed25519(key) => {
                #[cfg(feature = "aws-lc-rs")]
                {
                    let key =
                        aws_lc_rs::signature::Ed25519KeyPair::from_seed_unchecked(key.as_bytes())?;
                    Ok(key.sign(message).as_ref().to_vec())
                }
                #[cfg(not(feature = "aws-lc-rs"))]
                {
                    use ed25519_dalek::Signer;
                    Ok(key.try_sign(message)?.to_bytes().to_vec())
                }
            }
            #[allow(unreachable_patterns)]
            _ => bail!("Incompatible EdDSA private key."),
        }
    }

    pub(crate) fn derive(&self, peer: &PublicKey) -> anyhow::Result<Vec<u8>> {
        match (self, peer) {
            #[cfg(all(
                feature = "openssl",
                not(all(
                    any(feature = "ec-rustcrypto", feature = "aws-lc-rs"),
                    feature = "x25519-dalek",
                    feature = "x448-goldilocks-plus"
                ))
            ))]
            (Self::OpenSsl(key), PublicKey::OpenSsl(peer)) => {
                let mut deriver = Deriver::new(key)?;
                deriver.set_peer(peer)?;
                Ok(deriver.derive_to_vec()?)
            }
            #[cfg(feature = "x448-goldilocks-plus")]
            (Self::X448(key), PublicKey::X448(peer)) => {
                let shared = key.diffie_hellman(peer);
                if bool::from(shared.as_bytes().ct_eq(&[0; X448_LENGTH])) {
                    bail!("Invalid X448 shared secret.");
                }
                Ok(shared.as_bytes().to_vec())
            }
            #[cfg(any(feature = "ec-rustcrypto", feature = "aws-lc-rs"))]
            (Self::Ec(key), PublicKey::Ec(peer)) => key.derive(peer),
            #[cfg(feature = "x25519-dalek")]
            (Self::X25519(key), PublicKey::X25519(peer)) => {
                #[cfg(feature = "aws-lc-rs")]
                {
                    crate::aws_lc::derive(
                        &aws_lc_rs::agreement::X25519,
                        key.0.as_bytes(),
                        peer.as_bytes(),
                    )
                }
                #[cfg(not(feature = "aws-lc-rs"))]
                {
                    let shared = key.0.diffie_hellman(peer);
                    if !shared.was_contributory() {
                        bail!("Invalid X25519 shared secret.");
                    }
                    Ok(shared.as_bytes().to_vec())
                }
            }
            #[allow(unreachable_patterns)]
            _ => bail!("Incompatible ECDH keys."),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum PublicKey {
    #[cfg(all(
        feature = "openssl",
        not(all(
            any(feature = "ec-rustcrypto", feature = "aws-lc-rs"),
            any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"),
            feature = "ed25519-dalek",
            feature = "ed448-goldilocks-plus",
            feature = "x25519-dalek",
            feature = "x448-goldilocks-plus",
        ))
    ))]
    OpenSsl(PKey<Public>),
    #[cfg(any(feature = "ec-rustcrypto", feature = "aws-lc-rs"))]
    Ec(Box<ec::EcPublicKey>),
    #[cfg(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))]
    Rsa(Box<rsa_backend::Public>),
    #[cfg(feature = "ed25519-dalek")]
    Ed25519(ed25519_dalek::VerifyingKey),
    #[cfg(feature = "x25519-dalek")]
    X25519(x25519_dalek::PublicKey),
    #[cfg(feature = "ed448-goldilocks-plus")]
    Ed448(Box<VerifyingKey>),
    #[cfg(feature = "x448-goldilocks-plus")]
    X448(X448PublicKey),
}

impl PublicKey {
    pub(crate) fn from_der(der: &[u8], oid: &ObjectIdentifier) -> anyhow::Result<Self> {
        #[cfg(any(feature = "ec-rustcrypto", feature = "aws-lc-rs"))]
        if let Some(curve) = EcCurve::from_oid(oid) {
            return Ok(Self::Ec(Box::new(ec::EcPublicKey::from_der(der, curve)?)));
        }

        match oid {
            #[cfg(feature = "ed25519-dalek")]
            oid if oid == &*OID_ED25519 => {
                let bytes = okp::public_key_bytes(der, okp::ED25519_OID)?.try_into()?;
                Ok(Self::Ed25519(ed25519_dalek::VerifyingKey::from_bytes(
                    bytes,
                )?))
            }
            #[cfg(feature = "x25519-dalek")]
            oid if oid == &*OID_X25519 => {
                let bytes: [u8; 32] = okp::public_key_bytes(der, okp::X25519_OID)?.try_into()?;
                Ok(Self::X25519(x25519_dalek::PublicKey::from(bytes)))
            }
            #[cfg(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))]
            oid if oid == &*OID_RSA_ENCRYPTION || oid == &*OID_RSASSA_PSS => Ok(Self::Rsa(
                Box::new(rsa_backend::public_key_from_der(der, oid)?),
            )),
            #[cfg(feature = "ed448-goldilocks-plus")]
            oid if oid == &*OID_ED448 => {
                let bytes = okp::public_key_bytes(der, okp::ED448_OID)?.try_into()?;
                Ok(Self::Ed448(Box::new(VerifyingKey::from_bytes(bytes)?)))
            }
            #[cfg(feature = "x448-goldilocks-plus")]
            oid if oid == &*OID_X448 => {
                let bytes: [u8; X448_LENGTH] =
                    okp::public_key_bytes(der, okp::X448_OID)?.try_into()?;
                Ok(Self::X448(X448PublicKey::from(bytes)))
            }
            _ => {
                #[cfg(all(
                    feature = "openssl",
                    not(all(
                        any(feature = "ec-rustcrypto", feature = "aws-lc-rs"),
                        any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"),
                        feature = "ed25519-dalek",
                        feature = "ed448-goldilocks-plus",
                        feature = "x25519-dalek",
                        feature = "x448-goldilocks-plus",
                    ))
                ))]
                return Ok(Self::OpenSsl(PKey::public_key_from_der(der)?));
                #[cfg(not(all(
                    feature = "openssl",
                    not(all(
                        any(feature = "ec-rustcrypto", feature = "aws-lc-rs"),
                        any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"),
                        feature = "ed25519-dalek",
                        feature = "ed448-goldilocks-plus",
                        feature = "x25519-dalek",
                        feature = "x448-goldilocks-plus",
                    ))
                )))]
                bail!("Unsupported public key algorithm identifier: {oid}");
            }
        }
    }

    #[cfg(any(
        not(any(feature = "ec-rustcrypto", feature = "aws-lc-rs")),
        not(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))
    ))]
    fn as_openssl(&self) -> anyhow::Result<&PKeyRef<Public>> {
        match self {
            Self::OpenSsl(key) => Ok(key.as_ref()),
            #[allow(unreachable_patterns)]
            _ => bail!("This operation requires an OpenSSL public key."),
        }
    }

    pub(crate) fn rsa_size(&self) -> anyhow::Result<usize> {
        #[cfg(not(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs")))]
        return Ok(self.openssl_rsa()?.size() as usize);
        #[cfg(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))]
        Ok(rsa_backend::public_size(self.rsa()?))
    }

    #[cfg(not(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs")))]
    pub(crate) fn openssl_rsa(&self) -> anyhow::Result<Rsa<Public>> {
        Ok(self.as_openssl()?.rsa()?)
    }

    #[cfg(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))]
    fn rsa(&self) -> anyhow::Result<&rsa_backend::Public> {
        match self {
            Self::Rsa(key) => Ok(key),
            _ => bail!("Incompatible RSA public key."),
        }
    }

    pub(crate) fn rsa_public_der(&self) -> anyhow::Result<Vec<u8>> {
        #[cfg(not(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs")))]
        return Ok(self.openssl_rsa()?.public_key_to_der_pkcs1()?);
        #[cfg(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))]
        rsa_backend::export_public(self.rsa()?)
    }

    #[cfg(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))]
    pub(crate) fn rsa_verify(
        &self,
        hash: HashAlgorithm,
        pss: bool,
        message: &[u8],
        signature: &[u8],
    ) -> anyhow::Result<()> {
        rsa_backend::verify(self.rsa()?, hash, pss, message, signature)
    }

    #[cfg(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))]
    pub(crate) fn rsa_encrypt(
        &self,
        hash: Option<HashAlgorithm>,
        message: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        rsa_backend::encrypt(self.rsa()?, hash, message)
    }

    #[cfg(any(feature = "ec-rustcrypto", feature = "aws-lc-rs"))]
    pub(crate) fn verify_ecdsa(&self, message: &[u8], signature: &[u8]) -> anyhow::Result<()> {
        match self {
            Self::Ec(key) => key.verify(message, signature),
            _ => bail!("Incompatible ECDSA public key."),
        }
    }

    #[cfg(any(
        not(any(feature = "ec-rustcrypto", feature = "aws-lc-rs")),
        not(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs"))
    ))]
    pub(crate) fn openssl_verifier(&self, digest: MessageDigest) -> anyhow::Result<Verifier<'_>> {
        Ok(Verifier::new(digest, self.as_openssl()?)?)
    }

    #[cfg(not(any(feature = "rsa-rustcrypto", feature = "aws-lc-rs")))]
    pub(crate) fn openssl_encrypter(&self) -> anyhow::Result<Encrypter<'_>> {
        Ok(Encrypter::new(self.as_openssl()?)?)
    }

    pub(crate) fn verify_eddsa(&self, message: &[u8], signature: &[u8]) -> anyhow::Result<()> {
        match self {
            #[cfg(all(
                feature = "openssl",
                not(all(feature = "ed25519-dalek", feature = "ed448-goldilocks-plus"))
            ))]
            Self::OpenSsl(key) => {
                let mut verifier = Verifier::new_without_digest(key)?;
                if !verifier.verify_oneshot(signature, message)? {
                    bail!("The signature does not match.");
                }
            }
            #[cfg(feature = "ed448-goldilocks-plus")]
            Self::Ed448(key) => {
                let signature = Signature::try_from(signature)
                    .map_err(|err| anyhow::anyhow!("Invalid Ed448 signature: {err}"))?;
                key.verify_raw(&signature, message)?;
            }
            #[cfg(feature = "ed25519-dalek")]
            Self::Ed25519(key) => {
                #[cfg(feature = "aws-lc-rs")]
                {
                    use aws_lc_rs::signature::{UnparsedPublicKey, ED25519};
                    UnparsedPublicKey::new(&ED25519, key.as_bytes()).verify(message, signature)?;
                }
                #[cfg(not(feature = "aws-lc-rs"))]
                {
                    let signature = ed25519_dalek::Signature::try_from(signature)?;
                    key.verify_strict(message, &signature)?;
                }
            }
            #[allow(unreachable_patterns)]
            _ => bail!("Incompatible EdDSA public key."),
        }
        Ok(())
    }
}

pub(super) fn encode_okp_private_key(oid: &ObjectIdentifier, bytes: &[u8]) -> Vec<u8> {
    let mut builder = DerBuilder::new();
    builder.begin(DerType::Sequence);
    builder.append_integer_from_u8(0);
    builder.begin(DerType::Sequence);
    builder.append_object_identifier(oid);
    builder.end();
    let mut inner = DerBuilder::new();
    inner.append_octed_string_from_bytes(bytes);
    builder.append_octed_string_from_bytes(&inner.build());
    builder.end();
    builder.build()
}

pub(crate) fn encode_okp_public_key(oid: &ObjectIdentifier, bytes: &[u8]) -> Vec<u8> {
    let mut builder = DerBuilder::new();
    builder.begin(DerType::Sequence);
    builder.begin(DerType::Sequence);
    builder.append_object_identifier(oid);
    builder.end();
    builder.append_bit_string_from_bytes(bytes, 0);
    builder.end();
    builder.build()
}

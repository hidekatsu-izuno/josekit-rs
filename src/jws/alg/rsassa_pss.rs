use std::fmt::Display;
use std::ops::Deref;

use anyhow::bail;
#[cfg(feature = "kapun-provider")]
use kapun_crypto_provider::{KeyEncoding, Metadata, Signer, Signing, Verifier, Verifying};
#[cfg(feature = "openssl")]
use openssl::hash::MessageDigest;
#[cfg(feature = "openssl")]
use openssl::pkey::{PKey, Private, Public};
#[cfg(feature = "openssl")]
use openssl::rsa::Rsa;
#[cfg(feature = "openssl")]
use openssl::sign::{Signer, Verifier};
#[cfg(feature = "kapun-provider")]
use pkcs8::EncodePrivateKey;
#[cfg(feature = "rustcrypto")]
use rsa::pkcs1::DecodeRsaPublicKey;
#[cfg(feature = "rustcrypto")]
use rsa::pkcs8::der::Decode;
#[cfg(feature = "rustcrypto")]
use rsa::pkcs8::DecodePublicKey;
#[cfg(feature = "rustcrypto")]
use rsa::pkcs8::SubjectPublicKeyInfoRef;
#[cfg(feature = "kapun-provider")]
use spki::EncodePublicKey;

use crate::jwk::{
    alg::rsa::RsaKeyPair, alg::rsapss::RsaPssKeyPair, Jwk, PublicKey as PublicKeyTrait,
};
use crate::jws::{JwsAlgorithm, JwsSigner, JwsVerifier};
use crate::util::der::{DerBuilder, DerType};
use crate::util::{self, HashAlgorithm};
use crate::{JoseError, Value};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum RsassaPssJwsAlgorithm {
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    Ps256,
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    Ps384,
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    Ps512,
}

impl RsassaPssJwsAlgorithm {
    /// Generate RSA key pair.
    ///
    /// # Arguments
    /// * `bits` - RSA key length
    pub fn generate_key_pair(&self, bits: u32) -> Result<RsaPssKeyPair, JoseError> {
        (|| -> anyhow::Result<RsaPssKeyPair> {
            if bits < 2048 {
                bail!("key length must be 2048 or more.");
            }

            let mut key_pair = RsaPssKeyPair::generate(
                bits,
                self.hash_algorithm(),
                self.hash_algorithm(),
                self.salt_len(),
            )?;
            key_pair.set_algorithm(Some(self.name()));
            Ok(key_pair)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidKeyFormat(err),
        })
    }

    /// Create a RSA-PSS key pair from a private key that is a DER encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey.
    pub fn key_pair_from_der(&self, input: impl AsRef<[u8]>) -> Result<RsaPssKeyPair, JoseError> {
        (|| -> anyhow::Result<RsaPssKeyPair> {
            let mut key_pair = RsaPssKeyPair::from_der(
                input,
                Some(self.hash_algorithm()),
                Some(self.hash_algorithm()),
                Some(self.salt_len()),
            )?;

            if key_pair.key_len() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

            key_pair.set_algorithm(Some(self.name()));
            Ok(key_pair)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidKeyFormat(err),
        })
    }

    /// Create a RSA-PSS key pair from a private key of common or traditinal PEM format.
    ///
    /// Common PEM format is a DER and base64 encoded PKCS#8 PrivateKeyInfo
    /// that surrounded by "-----BEGIN/END PRIVATE KEY----".
    ///
    /// Traditional PEM format is a DER and base64 encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey
    /// that surrounded by "-----BEGIN/END RSA-PSS/RSA PRIVATE KEY----".
    ///
    /// # Arguments
    /// * `input` - A private key of common or traditinal PEM format.
    pub fn key_pair_from_pem(&self, input: impl AsRef<[u8]>) -> Result<RsaPssKeyPair, JoseError> {
        (|| -> anyhow::Result<RsaPssKeyPair> {
            let mut key_pair = RsaPssKeyPair::from_pem(
                input.as_ref(),
                Some(self.hash_algorithm()),
                Some(self.hash_algorithm()),
                Some(self.salt_len()),
            )?;

            if key_pair.key_len() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

            key_pair.set_algorithm(Some(self.name()));
            Ok(key_pair)
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidKeyFormat(err),
        })
    }

    /// Return a signer from a private key that is a DER encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey.
    pub fn signer_from_der(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<RsassaPssJwsSigner, JoseError> {
        let key_pair = self.key_pair_from_der(input.as_ref())?;
        Ok(RsassaPssJwsSigner {
            algorithm: self.clone(),
            private_key: key_pair.into_private_key(),
            key_id: None,
        })
    }

    /// Return a signer from a private key of common or traditinal PEM format.
    ///
    /// Common PEM format is a DER and base64 encoded PKCS#8 PrivateKeyInfo
    /// that surrounded by "-----BEGIN/END PRIVATE KEY----".
    ///
    /// Traditional PEM format is a DER and base64 encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey
    /// that surrounded by "-----BEGIN/END RSA-PSS/RSA PRIVATE KEY----".
    ///
    /// # Arguments
    /// * `input` - A private key of common or traditinal PEM format.
    pub fn signer_from_pem(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<RsassaPssJwsSigner, JoseError> {
        let key_pair = self.key_pair_from_pem(input.as_ref())?;
        Ok(RsassaPssJwsSigner {
            algorithm: self.clone(),
            private_key: key_pair.into_private_key(),
            key_id: None,
        })
    }

    /// Return a signer from a private key that is formatted by a JWK of RSA type.
    ///
    /// # Arguments
    /// * `jwk` - A private key that is formatted by a JWK of RSA type.
    pub fn signer_from_jwk(&self, jwk: &Jwk) -> Result<RsassaPssJwsSigner, JoseError> {
        (|| -> anyhow::Result<RsassaPssJwsSigner> {
            match jwk.key_use() {
                Some(val) if val == "sig" => {}
                None => {}
                Some(val) => bail!("A parameter use must be sig: {}", val),
            }
            if !jwk.is_for_key_operation("sign") {
                bail!("A parameter key_ops must contains sign.");
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }

            let key_pair = RsaPssKeyPair::from_jwk(
                jwk,
                self.hash_algorithm(),
                self.hash_algorithm(),
                self.salt_len(),
            )?;
            if key_pair.key_len() * 8 < 2048 {
                bail!("key length must be 2048 or more.");
            }

            let private_key = key_pair.into_private_key();
            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(RsassaPssJwsSigner {
                algorithm: self.clone(),
                private_key,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a public key that is a DER encoded SubjectPublicKeyInfo or PKCS#1 RSAPublicKey.
    ///
    /// # Arguments
    /// * `input` - A public key that is a DER encoded SubjectPublicKeyInfo or PKCS#1 RSAPublicKey.
    pub fn verifier_from_der(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<RsassaPssJwsVerifier, JoseError> {
        (|| -> anyhow::Result<RsassaPssJwsVerifier> {
            let input = input.as_ref();
            let spki_der_vec;
            #[allow(unused)]
            let spki_der = match RsaPssKeyPair::detect_pkcs8(input, true) {
                Some((hash, mgf1_hash, salt_len)) => {
                    if hash != self.hash_algorithm() {
                        bail!("The message digest parameter is mismatched: {}", hash);
                    } else if mgf1_hash != self.hash_algorithm() {
                        bail!(
                            "The mgf1 message digest parameter is mismatched: {}",
                            mgf1_hash
                        );
                    } else if salt_len != self.salt_len() {
                        bail!("The salt size is mismatched: {}", salt_len);
                    }

                    input.as_ref()
                }
                None => {
                    let rsa_der_vec;
                    let rsa_der = match RsaKeyPair::detect_pkcs8(input, true) {
                        #[cfg(feature = "openssl")]
                        Some(_) => {
                            let rsa = Rsa::public_key_from_der(input)?;
                            rsa_der_vec = rsa.public_key_to_der_pkcs1()?;
                            &rsa_der_vec
                        }
                        #[cfg(feature = "rustcrypto")]
                        Some(_) => {
                            use rsa::{pkcs1::EncodeRsaPublicKey, pkcs8::DecodePublicKey};
                            let rsa = rsa::RsaPublicKey::from_public_key_der(input)?;
                            rsa_der_vec = rsa.to_pkcs1_der()?;
                            &rsa_der_vec.as_bytes()
                        }
                        None => input,
                    };

                    spki_der_vec = RsaPssKeyPair::to_pkcs8(
                        rsa_der,
                        true,
                        self.hash_algorithm(),
                        self.hash_algorithm(),
                        self.salt_len(),
                    );
                    spki_der_vec.as_slice()
                }
            };
            #[cfg(feature = "rustcrypto")]
            let p = SubjectPublicKeyInfoRef::from_der(&input)?;
            #[cfg(feature = "openssl")]
            let public_key = PKey::public_key_from_der(spki_der)?;
            #[cfg(feature = "rustcrypto")]
            let public_key = rsa::RsaPublicKey::from_pkcs1_der(p.subject_public_key.raw_bytes())
                .or_else(|_| {
                    rsa::RsaPublicKey::from_public_key_der(p.subject_public_key.raw_bytes())
                })?;
            #[cfg(feature = "openssl")]
            {
                let rsa = public_key.rsa()?;
                if rsa.size() * 8 < 2048 {
                    bail!("key length must be 2048 or more.");
                }
            }
            #[cfg(feature = "rustcrypto")]
            {
                use rsa::traits::PublicKeyParts;
                if public_key.size() * 8 < 2048 {
                    bail!("key length must be 2048 or more.");
                }
            }

            Ok(RsassaPssJwsVerifier {
                algorithm: self.clone(),
                public_key,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a key of common or traditional PEM format.
    ///
    /// Common PEM format is a DER and base64 encoded SubjectPublicKeyInfo
    /// that surrounded by "-----BEGIN/END PUBLIC KEY----".
    ///
    /// Traditional PEM format is a DER and base64 SubjectPublicKeyInfo or PKCS#1 RSAPublicKey
    /// that surrounded by "-----BEGIN/END RSA-PSS/RSA PUBLIC KEY----".
    ///
    /// # Arguments
    /// * `input` - A public key of common or traditional PEM format.
    pub fn verifier_from_pem(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<RsassaPssJwsVerifier, JoseError> {
        (|| -> anyhow::Result<RsassaPssJwsVerifier> {
            let (alg, data) = util::parse_pem(input.as_ref())?;
            let public_key = match alg.as_str() {
                "PUBLIC KEY" => match RsaPssKeyPair::detect_pkcs8(&data, true) {
                    Some((hash, mgf1_hash, salt_len)) => {
                        if hash != self.hash_algorithm() {
                            bail!("The message digest parameter is mismatched: {}", hash);
                        } else if mgf1_hash != self.hash_algorithm() {
                            bail!(
                                "The mgf1 message digest parameter is mismatched: {}",
                                mgf1_hash
                            );
                        } else if salt_len != self.salt_len() {
                            bail!("The salt size is mismatched: {}", salt_len);
                        }
                        #[cfg(feature = "rustcrypto")]
                        let p = SubjectPublicKeyInfoRef::from_der(&data)?;
                        #[cfg(feature = "openssl")]
                        let public_key = PKey::public_key_from_der(&data)?;
                        #[cfg(feature = "rustcrypto")]
                        let public_key =
                            rsa::RsaPublicKey::from_pkcs1_der(&p.subject_public_key.raw_bytes())
                                .or_else(|_| {
                                    rsa::RsaPublicKey::from_public_key_der(
                                        &p.subject_public_key.raw_bytes(),
                                    )
                                })?;
                        #[cfg(feature = "openssl")]
                        {
                            let rsa = public_key.rsa()?;
                            if rsa.size() * 8 < 2048 {
                                bail!("key length must be 2048 or more.");
                            }
                        }
                        #[cfg(feature = "rustcrypto")]
                        {
                            use rsa::traits::PublicKeyParts;
                            if public_key.size() * 8 < 2048 {
                                bail!("key length must be 2048 or more.");
                            }
                        }
                        public_key
                    }
                    None => bail!("Invalid PEM contents."),
                },
                "RSA PUBLIC KEY" => {
                    let pkcs8 = RsaPssKeyPair::to_pkcs8(
                        &data,
                        true,
                        self.hash_algorithm(),
                        self.hash_algorithm(),
                        self.salt_len(),
                    );
                    #[cfg(feature = "rustcrypto")]
                    let p = SubjectPublicKeyInfoRef::from_der(&pkcs8)?;
                    #[cfg(feature = "openssl")]
                    let public_key = PKey::public_key_from_der(&pkcs8)?;
                    #[cfg(feature = "rustcrypto")]
                    let public_key =
                        rsa::RsaPublicKey::from_pkcs1_der(&p.subject_public_key.raw_bytes())
                            .or_else(|_| {
                                rsa::RsaPublicKey::from_public_key_der(
                                    &p.subject_public_key.raw_bytes(),
                                )
                            })?;
                    #[cfg(feature = "openssl")]
                    {
                        let rsa = public_key.rsa()?;
                        if rsa.size() * 8 < 2048 {
                            bail!("key length must be 2048 or more.");
                        }
                    }
                    #[cfg(feature = "rustcrypto")]
                    {
                        use rsa::traits::PublicKeyParts;
                        if public_key.size() * 8 < 2048 {
                            bail!("key length must be 2048 or more.");
                        }
                    }
                    public_key
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };

            Ok(RsassaPssJwsVerifier {
                algorithm: self.clone(),
                public_key,
                key_id: None,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a public key that is formatted by a JWK of RSA type.
    ///
    /// # Arguments
    /// * `jwk` - A public key that is formatted by a JWK of RSA type.
    pub fn verifier_from_jwk(&self, jwk: &Jwk) -> Result<RsassaPssJwsVerifier, JoseError> {
        (|| -> anyhow::Result<RsassaPssJwsVerifier> {
            match jwk.key_type() {
                val if val == "RSA" => {}
                val => bail!("A parameter kty must be RSA: {}", val),
            };
            match jwk.key_use() {
                Some(val) if val == "sig" => {}
                None => {}
                Some(val) => bail!("A parameter use must be sig: {}", val),
            };
            if !jwk.is_for_key_operation("verify") {
                bail!("A parameter key_ops must contains verify.");
            }
            match jwk.algorithm() {
                Some(val) if val == self.name() => {}
                None => {}
                Some(val) => bail!("A parameter alg must be {} but {}", self.name(), val),
            }
            let n = match jwk.parameter("n") {
                Some(Value::String(val)) => util::decode_base64_urlsafe_no_pad(val)?,
                Some(_) => bail!("A parameter n must be a string."),
                None => bail!("A parameter n is required."),
            };
            let e = match jwk.parameter("e") {
                Some(Value::String(val)) => util::decode_base64_urlsafe_no_pad(val)?,
                Some(_) => bail!("A parameter e must be a string."),
                None => bail!("A parameter e is required."),
            };

            let mut builder = DerBuilder::new();
            builder.begin(DerType::Sequence);
            {
                builder.append_integer_from_be_slice(&n, true); // n
                builder.append_integer_from_be_slice(&e, true); // e
            }
            builder.end();
            #[cfg(feature = "openssl")]
            let pkcs8 = RsaPssKeyPair::to_pkcs8(
                &builder.build(),
                true,
                self.hash_algorithm(),
                self.hash_algorithm(),
                self.salt_len(),
            );

            #[cfg(feature = "openssl")]
            let public_key = PKey::public_key_from_der(&pkcs8)?;
            #[cfg(feature = "rustcrypto")]
            let public_key = rsa::RsaPublicKey::from_pkcs1_der(&builder.build())?;
            #[cfg(feature = "openssl")]
            {
                let rsa = public_key.rsa()?;
                if rsa.size() * 8 < 2048 {
                    bail!("key length must be 2048 or more.");
                }
            }
            #[cfg(feature = "rustcrypto")]
            {
                use rsa::traits::PublicKeyParts;
                if public_key.size() * 8 < 2048 {
                    bail!("key length must be 2048 or more.");
                }
            }
            let key_id = jwk.key_id().map(|val| val.to_string());

            Ok(RsassaPssJwsVerifier {
                algorithm: self.clone(),
                public_key,
                key_id,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn hash_algorithm(&self) -> HashAlgorithm {
        match self {
            Self::Ps256 => HashAlgorithm::Sha256,
            Self::Ps384 => HashAlgorithm::Sha384,
            Self::Ps512 => HashAlgorithm::Sha512,
        }
    }

    fn salt_len(&self) -> u8 {
        match self {
            Self::Ps256 => 32,
            Self::Ps384 => 48,
            Self::Ps512 => 64,
        }
    }
}

impl JwsAlgorithm for RsassaPssJwsAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::Ps256 => "PS256",
            Self::Ps384 => "PS384",
            Self::Ps512 => "PS512",
        }
    }

    fn box_clone(&self) -> Box<dyn JwsAlgorithm> {
        Box::new(self.clone())
    }
}

impl Display for RsassaPssJwsAlgorithm {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.write_str(self.name())
    }
}

impl Deref for RsassaPssJwsAlgorithm {
    type Target = dyn JwsAlgorithm;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct RsassaPssJwsSigner {
    algorithm: RsassaPssJwsAlgorithm,
    #[cfg(feature = "openssl")]
    private_key: PKey<Private>,
    #[cfg(feature = "rustcrypto")]
    private_key: rsa::RsaPrivateKey,
    key_id: Option<String>,
}

impl RsassaPssJwsSigner {
    pub fn set_key_id(&mut self, value: impl Into<String>) {
        self.key_id = Some(value.into());
    }

    pub fn remove_key_id(&mut self) {
        self.key_id = None;
    }
}

impl JwsSigner for RsassaPssJwsSigner {
    fn algorithm(&self) -> &dyn JwsAlgorithm {
        &self.algorithm
    }

    fn signature_len(&self) -> usize {
        256
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    #[cfg(feature = "openssl")]
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let md = match &self.algorithm.hash_algorithm() {
                HashAlgorithm::Sha1 => MessageDigest::sha1(),
                HashAlgorithm::Sha256 => MessageDigest::sha256(),
                HashAlgorithm::Sha384 => MessageDigest::sha384(),
                HashAlgorithm::Sha512 => MessageDigest::sha512(),
            };
            let mut signer = Signer::new(md, &self.private_key)?;
            signer.update(message)?;
            let signature = signer.sign_to_vec()?;
            Ok(signature)
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }
    #[cfg(feature = "rustcrypto")]
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            use rsa::{traits::SignatureScheme, Pss};
            use sha1::Sha1;
            use sha2::{Sha256, Sha384, Sha512};
            let mut rng = rand::rng();

            use crate::jwe::alg::pbes2_hmac_aeskw::MessageDigest;
            let md = match &self.algorithm.hash_algorithm() {
                HashAlgorithm::Sha1 => MessageDigest::sha1(),
                HashAlgorithm::Sha256 => MessageDigest::sha256(),
                HashAlgorithm::Sha384 => MessageDigest::sha384(),
                HashAlgorithm::Sha512 => MessageDigest::sha512(),
            };
            let signature = match &self.algorithm.hash_algorithm() {
                HashAlgorithm::Sha1 => {
                    let signer = Pss::<Sha1>::new();
                    signer.sign(Some(&mut rng), &self.private_key, &md.hash(message))?
                }
                HashAlgorithm::Sha256 => {
                    let signer = Pss::<Sha256>::new();
                    signer.sign(Some(&mut rng), &self.private_key, &md.hash(message))?
                }
                HashAlgorithm::Sha384 => {
                    let signer = Pss::<Sha384>::new();
                    signer.sign(Some(&mut rng), &self.private_key, &md.hash(message))?
                }
                HashAlgorithm::Sha512 => {
                    let signer = Pss::<Sha512>::new();
                    signer.sign(Some(&mut rng), &self.private_key, &md.hash(message))?
                }
            };

            Ok(signature)
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }
    #[cfg(feature = "rustcrypto")]
    fn sign_prehashed(&self, digest: &[u8]) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            use rsa::{traits::SignatureScheme, Pss};
            use sha1::Sha1;
            use sha2::{Sha256, Sha384, Sha512};
            let mut rng = rand::rng();

            let signature = match &self.algorithm.hash_algorithm() {
                HashAlgorithm::Sha1 => {
                    let signer = Pss::<Sha1>::new();
                    signer.sign(Some(&mut rng), &self.private_key, digest)?
                }
                HashAlgorithm::Sha256 => {
                    let signer = Pss::<Sha256>::new();
                    signer.sign(Some(&mut rng), &self.private_key, digest)?
                }
                HashAlgorithm::Sha384 => {
                    let signer = Pss::<Sha384>::new();
                    signer.sign(Some(&mut rng), &self.private_key, digest)?
                }
                HashAlgorithm::Sha512 => {
                    let signer = Pss::<Sha512>::new();
                    signer.sign(Some(&mut rng), &self.private_key, digest)?
                }
            };

            Ok(signature)
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }

    fn box_clone(&self) -> Box<dyn JwsSigner> {
        Box::new(self.clone())
    }
}

impl Deref for RsassaPssJwsSigner {
    type Target = dyn JwsSigner;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[derive(Debug, Clone)]
pub struct RsassaPssJwsVerifier {
    algorithm: RsassaPssJwsAlgorithm,
    #[cfg(feature = "openssl")]
    public_key: PKey<Public>,
    #[cfg(feature = "rustcrypto")]
    public_key: rsa::RsaPublicKey,
    key_id: Option<String>,
}

impl RsassaPssJwsVerifier {
    pub fn set_key_id(&mut self, value: impl Into<String>) {
        self.key_id = Some(value.into());
    }

    pub fn remove_key_id(&mut self) {
        self.key_id = None;
    }
}

impl PublicKeyTrait for RsassaPssJwsVerifier {
    fn to_der_public_key(&self) -> Vec<u8> {
        PublicKeyTrait::to_der_public_key(&self.public_key)
    }

    fn to_pem_public_key(&self) -> Vec<u8> {
        PublicKeyTrait::to_pem_public_key(&self.public_key)
    }

    fn to_jwk_public_key(&self) -> Jwk {
        let mut jwk = PublicKeyTrait::to_jwk_public_key(&self.public_key);
        jwk.set_algorithm(self.algorithm.name());
        if let Some(key_id) = &self.key_id {
            jwk.set_key_id(key_id);
        }
        jwk
    }
}

impl JwsVerifier for RsassaPssJwsVerifier {
    fn algorithm(&self) -> &dyn JwsAlgorithm {
        &self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        match &self.key_id {
            Some(val) => Some(val.as_ref()),
            None => None,
        }
    }

    #[cfg(feature = "openssl")]
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            let md = match &self.algorithm.hash_algorithm() {
                HashAlgorithm::Sha1 => MessageDigest::sha1(),
                HashAlgorithm::Sha256 => MessageDigest::sha256(),
                HashAlgorithm::Sha384 => MessageDigest::sha384(),
                HashAlgorithm::Sha512 => MessageDigest::sha512(),
            };
            let mut verifier = Verifier::new(md, &self.public_key)?;
            verifier.update(message)?;
            if !verifier.verify(signature)? {
                bail!("The signature does not match.");
            }
            Ok(())
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }
    #[cfg(feature = "rustcrypto")]
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            use rsa::{traits::SignatureScheme, Pss};
            use sha1::Sha1;
            use sha2::{Sha256, Sha384, Sha512};

            use crate::jwe::alg::pbes2_hmac_aeskw::MessageDigest;
            let md = match &self.algorithm.hash_algorithm() {
                HashAlgorithm::Sha1 => MessageDigest::sha1(),
                HashAlgorithm::Sha256 => MessageDigest::sha256(),
                HashAlgorithm::Sha384 => MessageDigest::sha384(),
                HashAlgorithm::Sha512 => MessageDigest::sha512(),
            };
            match &self.algorithm.hash_algorithm() {
                HashAlgorithm::Sha1 => {
                    let verifier = Pss::<Sha1>::new();
                    if verifier
                        .verify(&self.public_key, &md.hash(message), signature)
                        .is_err()
                    {
                        bail!("The signature does not match.");
                    }
                }
                HashAlgorithm::Sha256 => {
                    let verifier = Pss::<Sha256>::new();
                    if verifier
                        .verify(&self.public_key, &md.hash(message), signature)
                        .is_err()
                    {
                        bail!("The signature does not match.");
                    }
                }
                HashAlgorithm::Sha384 => {
                    let verifier = Pss::<Sha384>::new();
                    if verifier
                        .verify(&self.public_key, &md.hash(message), signature)
                        .is_err()
                    {
                        bail!("The signature does not match.");
                    }
                }
                HashAlgorithm::Sha512 => {
                    let verifier = Pss::<Sha512>::new();
                    if verifier
                        .verify(&self.public_key, &md.hash(message), signature)
                        .is_err()
                    {
                        bail!("The signature does not match.");
                    }
                }
            };

            Ok(())
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }

    fn box_clone(&self) -> Box<dyn JwsVerifier> {
        Box::new(self.clone())
    }
}

impl Deref for RsassaPssJwsVerifier {
    type Target = dyn JwsVerifier;

    fn deref(&self) -> &Self::Target {
        self
    }
}

#[cfg(feature = "kapun-provider")]
impl KeyEncoding for RsassaPssJwsSigner {
    fn kapun_private_pkcs8_der(&self) -> Option<Vec<u8>> {
        Some(self.private_key.to_pkcs8_der().ok()?.to_bytes().to_vec())
    }

    fn kapun_private_pkcs8_pem(&self) -> Option<String> {
        Some(
            self.private_key
                .to_pkcs8_pem(pkcs8::LineEnding::CRLF)
                .ok()?
                .to_string(),
        )
    }

    fn kapun_public_spki_der(&self) -> Option<Vec<u8>> {
        Some(
            self.private_key
                .as_public_key()
                .to_public_key_der()
                .ok()?
                .to_vec(),
        )
    }

    fn kapun_public_spki_pem(&self) -> Option<String> {
        Some(
            self.private_key
                .as_public_key()
                .to_public_key_pem(pkcs8::LineEnding::CRLF)
                .ok()?,
        )
    }
}
#[cfg(feature = "kapun-provider")]
impl KeyEncoding for RsassaPssJwsVerifier {
    fn kapun_public_spki_der(&self) -> Option<Vec<u8>> {
        Some(self.public_key.to_public_key_der().ok()?.to_vec())
    }

    fn kapun_public_spki_pem(&self) -> Option<String> {
        Some(
            self.public_key
                .to_public_key_pem(pkcs8::LineEnding::CRLF)
                .ok()?,
        )
    }
}

#[cfg(feature = "kapun-provider")]
impl Signing for RsassaPssJwsSigner {
    fn kapun_sign(&self, data: Vec<u8>) -> Result<Vec<u8>, kapun_crypto_provider::SigningProblem> {
        self.sign(&data)
            .map_err(|_| kapun_crypto_provider::SigningProblem::SigningFailed)
    }

    fn kapun_sign_hash(
        &self,
        hash: Vec<u8>,
    ) -> Result<Vec<u8>, kapun_crypto_provider::SigningProblem> {
        self.sign_prehashed(&hash)
            .map_err(|_| kapun_crypto_provider::SigningProblem::SigningFailed)
    }
}

#[cfg(feature = "kapun-provider")]
impl Verifying for RsassaPssJwsVerifier {
    fn kapun_verify(
        &self,
        data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<(), kapun_crypto_provider::VerificationProblem> {
        self.verify(&data, &signature)
            .map_err(|_| kapun_crypto_provider::VerificationProblem::SignatureInvalid)
    }
    // TODO: we should use a prehashed version here
    fn kapun_verify_hash(
        &self,
        hash: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<(), kapun_crypto_provider::VerificationProblem> {
        self.verify_prehashed(&hash, &signature)
            .map_err(|_| kapun_crypto_provider::VerificationProblem::SignatureInvalid)
    }
}

#[cfg(feature = "kapun-provider")]
impl Metadata for RsassaPssJwsSigner {
    fn kapun_jose_alg(&self) -> Option<String> {
        Some(self.algorithm.name().to_string())
    }
}
#[cfg(feature = "kapun-provider")]
impl Metadata for RsassaPssJwsVerifier {
    fn kapun_jose_alg(&self) -> Option<String> {
        Some(self.algorithm.name().to_string())
    }
}

#[cfg(feature = "kapun-provider")]
impl Signer for RsassaPssJwsSigner {}
#[cfg(feature = "kapun-provider")]
impl Verifier for RsassaPssJwsVerifier {}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Result;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn sign_and_verify_rsassa_pss_generated_der() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsassaPssJwsAlgorithm::Ps256,
            RsassaPssJwsAlgorithm::Ps384,
            RsassaPssJwsAlgorithm::Ps512,
        ] {
            let key_pair = alg.generate_key_pair(2048)?;

            let signer = alg.signer_from_der(&key_pair.to_der_private_key())?;
            let signature = signer.sign(input)?;
            let verifier = alg.verifier_from_der(&key_pair.to_der_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsassa_pss_generated_rsa_der() -> Result<()> {
        let input = b"abcde12345";

        let key_pair = RsaKeyPair::generate(2048)?;
        for alg in &[
            RsassaPssJwsAlgorithm::Ps256,
            RsassaPssJwsAlgorithm::Ps384,
            RsassaPssJwsAlgorithm::Ps512,
        ] {
            println!("verifier {alg:?}");
            let verifier = alg.verifier_from_der(&key_pair.to_raw_public_key())?;
            println!("signer");
            let signer = alg.signer_from_der(&key_pair.to_der_private_key())?;
            let signature = signer.sign(input)?;

            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsassa_pss_generated_raw() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsassaPssJwsAlgorithm::Ps256,
            RsassaPssJwsAlgorithm::Ps384,
            RsassaPssJwsAlgorithm::Ps512,
        ] {
            let key_pair = alg.generate_key_pair(2048)?;
            println!("before");
            let signer = alg.signer_from_der(&key_pair.to_raw_private_key())?;
            println!("after 1");
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_der(&key_pair.to_der_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsassa_pss_generated_pem() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsassaPssJwsAlgorithm::Ps256,
            RsassaPssJwsAlgorithm::Ps384,
            RsassaPssJwsAlgorithm::Ps512,
        ] {
            let key_pair = alg.generate_key_pair(2048)?;
            println!("test1");
            let signer = alg.signer_from_pem(&key_pair.to_pem_private_key())?;
            let signature = signer.sign(input)?;
            println!("test2");
            let verifier = alg.verifier_from_pem(&key_pair.to_pem_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsassa_pss_generated_traditional_pem() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsassaPssJwsAlgorithm::Ps256,
            RsassaPssJwsAlgorithm::Ps384,
            RsassaPssJwsAlgorithm::Ps512,
        ] {
            let key_pair = alg.generate_key_pair(2048)?;

            let signer = alg.signer_from_pem(&key_pair.to_traditional_pem_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_pem(&key_pair.to_pem_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsassa_pss_generated_jwk() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsassaPssJwsAlgorithm::Ps256,
            RsassaPssJwsAlgorithm::Ps384,
            RsassaPssJwsAlgorithm::Ps512,
        ] {
            let key_pair = alg.generate_key_pair(2048)?;

            let signer = alg.signer_from_jwk(&key_pair.to_jwk_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_jwk(&key_pair.to_jwk_public_key())?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsassa_pss_jwt() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsassaPssJwsAlgorithm::Ps256,
            RsassaPssJwsAlgorithm::Ps384,
            RsassaPssJwsAlgorithm::Ps512,
        ] {
            let private_key = load_file("jwk/RSA_private.jwk")?;
            let public_key = load_file("jwk/RSA_public.jwk")?;

            let signer = alg.signer_from_jwk(&Jwk::from_bytes(&private_key)?)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_jwk(&Jwk::from_bytes(&public_key)?)?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsassa_pss_pkcs8_pem() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsassaPssJwsAlgorithm::Ps256,
            RsassaPssJwsAlgorithm::Ps384,
            RsassaPssJwsAlgorithm::Ps512,
        ] {
            let private_key = load_file(match alg {
                RsassaPssJwsAlgorithm::Ps256 => "pem/RSA-PSS_2048bit_SHA-256_private.pem",
                RsassaPssJwsAlgorithm::Ps384 => "pem/RSA-PSS_2048bit_SHA-384_private.pem",
                RsassaPssJwsAlgorithm::Ps512 => "pem/RSA-PSS_2048bit_SHA-512_private.pem",
            })?;
            let public_key = load_file(match alg {
                RsassaPssJwsAlgorithm::Ps256 => "pem/RSA-PSS_2048bit_SHA-256_public.pem",
                RsassaPssJwsAlgorithm::Ps384 => "pem/RSA-PSS_2048bit_SHA-384_public.pem",
                RsassaPssJwsAlgorithm::Ps512 => "pem/RSA-PSS_2048bit_SHA-512_public.pem",
            })?;

            let signer = alg.signer_from_pem(&private_key)?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsassa_pss_pkcs8_der() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsassaPssJwsAlgorithm::Ps256,
            RsassaPssJwsAlgorithm::Ps384,
            RsassaPssJwsAlgorithm::Ps512,
        ] {
            let private_key = load_file(match alg {
                RsassaPssJwsAlgorithm::Ps256 => "der/RSA-PSS_2048bit_SHA-256_pkcs8_private.der",
                RsassaPssJwsAlgorithm::Ps384 => "der/RSA-PSS_2048bit_SHA-384_pkcs8_private.der",
                RsassaPssJwsAlgorithm::Ps512 => "der/RSA-PSS_2048bit_SHA-512_pkcs8_private.der",
            })?;
            let public_key = load_file(match alg {
                RsassaPssJwsAlgorithm::Ps256 => "der/RSA-PSS_2048bit_SHA-256_spki_public.der",
                RsassaPssJwsAlgorithm::Ps384 => "der/RSA-PSS_2048bit_SHA-384_spki_public.der",
                RsassaPssJwsAlgorithm::Ps512 => "der/RSA-PSS_2048bit_SHA-512_spki_public.der",
            })?;
            println!("signer");
            let signer = alg.signer_from_der(&private_key)?;
            let signature = signer.sign(input)?;

            println!("verifier");
            let verifier = alg.verifier_from_der(&public_key)?;
            verifier.verify(input, &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsassa_pss_mismatch() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsassaPssJwsAlgorithm::Ps256,
            RsassaPssJwsAlgorithm::Ps384,
            RsassaPssJwsAlgorithm::Ps512,
        ] {
            let signer_key_pair = alg.generate_key_pair(2048)?;
            let verifier_key_pair = alg.generate_key_pair(2048)?;

            let signer = alg.signer_from_der(&signer_key_pair.to_der_private_key())?;
            let signature = signer.sign(input)?;

            let verifier = alg.verifier_from_der(&verifier_key_pair.to_der_public_key())?;
            verifier
                .verify(input, &signature)
                .expect_err("Unmatched signature did not fail");
        }

        Ok(())
    }

    fn load_file(path: &str) -> Result<Vec<u8>> {
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push("data");
        pb.push(path);

        let data = fs::read(&pb)?;
        Ok(data)
    }
}

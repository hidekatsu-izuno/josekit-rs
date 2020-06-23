use anyhow::bail;
use once_cell::sync::Lazy;
use openssl::hash::MessageDigest;
use openssl::pkey::{HasPublic, PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use serde_json::{Map, Value};
use std::io::Read;

use crate::der::oid::ObjectIdentifier;
use crate::der::{DerBuilder, DerClass, DerReader, DerType};
use crate::error::JoseError;
use crate::jws::util::{json_base64_bytes, json_eq, parse_pem};
use crate::jws::{JwsAlgorithm, JwsSigner, JwsVerifier};

static OID_RSASSA_PSS: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 10]));

static OID_SHA256: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 16, 840, 1, 101, 3, 4, 2, 1]));

static OID_SHA384: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 16, 840, 1, 101, 3, 4, 2, 2]));

static OID_SHA512: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[2, 16, 840, 1, 101, 3, 4, 2, 3]));

static OID_MGF1: Lazy<ObjectIdentifier> =
    Lazy::new(|| ObjectIdentifier::from_slice(&[1, 2, 840, 113549, 1, 1, 8]));

#[derive(Debug, Eq, PartialEq)]
pub enum RsaPssJwsAlgorithm {
    /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    PS256,
    /// RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    PS384,
    /// RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    PS512,
}

impl RsaPssJwsAlgorithm {
    /// Return a signer from a private key of RSA JWK format.
    ///
    /// # Arguments
    /// * `input` - A private key of RSA JWK format.
    pub fn signer_from_jwk(&self, input: impl AsRef<[u8]>) -> Result<RsaPssJwsSigner, JoseError> {
        (|| -> anyhow::Result<RsaPssJwsSigner> {
            let map: Map<String, Value> = serde_json::from_slice(input.as_ref())?;

            json_eq(&map, "kty", "RSA", true)?;
            json_eq(&map, "use", "sig", false)?;
            json_eq(&map, "alg", &self.name(), false)?;
            let n = json_base64_bytes(&map, "n")?;
            let e = json_base64_bytes(&map, "e")?;
            let d = json_base64_bytes(&map, "d")?;
            let p = json_base64_bytes(&map, "p")?;
            let q = json_base64_bytes(&map, "q")?;
            let dp = json_base64_bytes(&map, "dp")?;
            let dq = json_base64_bytes(&map, "dq")?;
            let qi = json_base64_bytes(&map, "qi")?;

            let mut builder = DerBuilder::new();
            builder.begin(DerType::Sequence);
            {
                builder.append_integer_from_u8(0); // version
                builder.append_integer_from_be_slice(&n); // n
                builder.append_integer_from_be_slice(&e); // e
                builder.append_integer_from_be_slice(&d); // d
                builder.append_integer_from_be_slice(&p); // p
                builder.append_integer_from_be_slice(&q); // q
                builder.append_integer_from_be_slice(&dp); // d mod (p-1)
                builder.append_integer_from_be_slice(&dq); // d mod (q-1)
                builder.append_integer_from_be_slice(&qi); // (inverse of q) mod p
            }
            builder.end();

            let pkcs8 = self.to_pkcs8(&builder.build(), false);
            let pkey = PKey::private_key_from_der(&pkcs8)?;
            self.check_key(&pkey)?;

            Ok(RsaPssJwsSigner {
                algorithm: &self,
                private_key: pkey,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
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
    pub fn signer_from_pem(&self, input: impl AsRef<[u8]>) -> Result<RsaPssJwsSigner, JoseError> {
        (|| -> anyhow::Result<RsaPssJwsSigner> {
            let (alg, data) = parse_pem(input.as_ref())?;

            let pkey = match alg.as_str() {
                "PRIVATE KEY" | "RSA-PSS PRIVATE KEY" => {
                    if !self.detect_pkcs8(&data, false)? {
                        bail!("Invalid PEM contents.");
                    }
                    PKey::private_key_from_der(&data)?
                }
                "RSA PRIVATE KEY" => {
                    let pkcs8 = self.to_pkcs8(&data, false);
                    PKey::private_key_from_der(&pkcs8)?
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };
            self.check_key(&pkey)?;

            Ok(RsaPssJwsSigner {
                algorithm: &self,
                private_key: pkey,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a signer from a private key that is a DER encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey.
    ///
    /// # Arguments
    /// * `input` - A private key that is a DER encoded PKCS#8 PrivateKeyInfo or PKCS#1 RSAPrivateKey.
    pub fn signer_from_der(&self, input: impl AsRef<[u8]>) -> Result<RsaPssJwsSigner, JoseError> {
        (|| -> anyhow::Result<RsaPssJwsSigner> {
            let pkcs8;
            let pkcs8_ref = if self.detect_pkcs8(input.as_ref(), false)? {
                input.as_ref()
            } else {
                pkcs8 = self.to_pkcs8(input.as_ref(), false);
                &pkcs8
            };

            let pkey = PKey::private_key_from_der(pkcs8_ref)?;
            self.check_key(&pkey)?;

            Ok(RsaPssJwsSigner {
                algorithm: &self,
                private_key: pkey,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    /// Return a verifier from a key of RSA JWK format.
    ///
    /// # Arguments
    /// * `input` - A key of RSA JWK format.
    pub fn verifier_from_jwk(
        &self,
        input: impl AsRef<[u8]>,
    ) -> Result<RsaPssJwsVerifier, JoseError> {
        (|| -> anyhow::Result<RsaPssJwsVerifier> {
            let map: Map<String, Value> = serde_json::from_slice(input.as_ref())?;

            json_eq(&map, "kty", "RSA", true)?;
            json_eq(&map, "use", "sig", false)?;
            json_eq(&map, "alg", &self.name(), false)?;
            let n = json_base64_bytes(&map, "n")?;
            let e = json_base64_bytes(&map, "e")?;

            let mut builder = DerBuilder::new();
            builder.begin(DerType::Sequence);
            {
                builder.append_integer_from_be_slice(&n); // n
                builder.append_integer_from_be_slice(&e); // e
            }
            builder.end();

            let pkcs8 = self.to_pkcs8(&builder.build(), true);
            let pkey = PKey::public_key_from_der(&pkcs8)?;

            self.check_key(&pkey)?;

            Ok(RsaPssJwsVerifier {
                algorithm: &self,
                public_key: pkey,
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
    ) -> Result<RsaPssJwsVerifier, JoseError> {
        (|| -> anyhow::Result<RsaPssJwsVerifier> {
            let (alg, data) = parse_pem(input.as_ref())?;
            let pkey = match alg.as_str() {
                "PUBLIC KEY" | "RSA-PSS PUBLIC KEY" => {
                    if !self.detect_pkcs8(&data, true)? {
                        bail!("Invalid PEM contents.");
                    }
                    PKey::public_key_from_der(&data)?
                }
                "RSA PUBLIC KEY" => {
                    let pkcs8 = self.to_pkcs8(&data, true);
                    PKey::public_key_from_der(&pkcs8)?
                }
                alg => bail!("Inappropriate algorithm: {}", alg),
            };
            self.check_key(&pkey)?;

            Ok(RsaPssJwsVerifier {
                algorithm: &self,
                public_key: pkey,
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
    ) -> Result<RsaPssJwsVerifier, JoseError> {
        (|| -> anyhow::Result<RsaPssJwsVerifier> {
            let pkcs8;
            let pkcs8_ref = if self.detect_pkcs8(input.as_ref(), true)? {
                input.as_ref()
            } else {
                pkcs8 = self.to_pkcs8(input.as_ref(), true);
                &pkcs8
            };

            let pkey = PKey::public_key_from_der(pkcs8_ref)?;
            self.check_key(&pkey)?;

            Ok(RsaPssJwsVerifier {
                algorithm: &self,
                public_key: pkey,
            })
        })()
        .map_err(|err| JoseError::InvalidKeyFormat(err))
    }

    fn digest(&self) -> &ObjectIdentifier {
        match self {
            RsaPssJwsAlgorithm::PS256 => &OID_SHA256,
            RsaPssJwsAlgorithm::PS384 => &OID_SHA384,
            RsaPssJwsAlgorithm::PS512 => &OID_SHA512,
        }
    }

    fn salt_len(&self) -> u8 {
        match self {
            RsaPssJwsAlgorithm::PS256 => 32,
            RsaPssJwsAlgorithm::PS384 => 48,
            RsaPssJwsAlgorithm::PS512 => 64,
        }
    }

    fn check_key<T: HasPublic>(&self, pkey: &PKey<T>) -> anyhow::Result<()> {
        let rsa = pkey.rsa()?;

        if rsa.size() * 8 < 2048 {
            bail!("key length must be 2048 or more.");
        }

        Ok(())
    }

    fn detect_pkcs8(&self, input: &[u8], is_public: bool) -> anyhow::Result<bool> {
        let mut reader = DerReader::new(input.bytes());

        match reader.next() {
            Ok(Some(DerType::Sequence)) => {}
            _ => return Ok(false),
        }

        {
            if !is_public {
                // Version
                match reader.next() {
                    Ok(Some(DerType::Integer)) => match reader.to_u8() {
                        Ok(val) => {
                            if val != 0 {
                                bail!("Unrecognized version: {}", val);
                            }
                        }
                        _ => return Ok(false),
                    },
                    _ => return Ok(false),
                }
            }

            match reader.next() {
                Ok(Some(DerType::Sequence)) => {}
                _ => return Ok(false),
            }

            {
                match reader.next() {
                    Ok(Some(DerType::ObjectIdentifier)) => match reader.to_object_identifier() {
                        Ok(val) => {
                            if val != *OID_RSASSA_PSS {
                                bail!("Incompatible oid: {}", val);
                            }
                        }
                        _ => return Ok(false),
                    },
                    _ => return Ok(false),
                }

                match reader.next() {
                    Ok(Some(DerType::Sequence)) => {}
                    _ => return Ok(false),
                }

                {
                    match reader.next() {
                        Ok(Some(DerType::Other(DerClass::ContextSpecific, 0))) => {}
                        _ => return Ok(false),
                    }

                    match reader.next() {
                        Ok(Some(DerType::Sequence)) => {}
                        _ => return Ok(false),
                    }

                    {
                        match reader.next() {
                            Ok(Some(DerType::ObjectIdentifier)) => {
                                match reader.to_object_identifier() {
                                    Ok(val) => {
                                        if val != *self.digest() {
                                            bail!("Incompatible oid: {}", val);
                                        }
                                    }
                                    _ => return Ok(false),
                                }
                            }
                            _ => return Ok(false),
                        }
                    }

                    match reader.next() {
                        Ok(Some(DerType::EndOfContents)) => {}
                        _ => return Ok(false),
                    }

                    match reader.next() {
                        Ok(Some(DerType::Other(DerClass::ContextSpecific, 1))) => {}
                        _ => return Ok(false),
                    }

                    match reader.next() {
                        Ok(Some(DerType::Sequence)) => {}
                        _ => return Ok(false),
                    }

                    {
                        match reader.next() {
                            Ok(Some(DerType::ObjectIdentifier)) => {
                                match reader.to_object_identifier() {
                                    Ok(val) => {
                                        if val != *OID_MGF1 {
                                            bail!("Incompatible oid: {}", val);
                                        }
                                    }
                                    _ => return Ok(false),
                                }
                            }
                            _ => return Ok(false),
                        }

                        match reader.next() {
                            Ok(Some(DerType::Sequence)) => {}
                            _ => return Ok(false),
                        }

                        {
                            match reader.next() {
                                Ok(Some(DerType::ObjectIdentifier)) => {
                                    match reader.to_object_identifier() {
                                        Ok(val) => {
                                            if val != *self.digest() {
                                                bail!("Incompatible oid: {}", val);
                                            }
                                        }
                                        _ => return Ok(false),
                                    }
                                }
                                _ => return Ok(false),
                            }
                        }
                    }

                    match reader.next() {
                        Ok(Some(DerType::EndOfContents)) => {}
                        _ => return Ok(false),
                    }

                    match reader.next() {
                        Ok(Some(DerType::Other(DerClass::ContextSpecific, 2))) => {}
                        _ => return Ok(false),
                    }

                    match reader.next() {
                        Ok(Some(DerType::Integer)) => match reader.to_u8() {
                            Ok(val) => {
                                if val != self.salt_len() {
                                    bail!("Incompatible salt length: {}", val);
                                }
                            }
                            _ => return Ok(false),
                        },
                        _ => return Ok(false),
                    }
                }
            }
        }

        Ok(true)
    }

    fn to_pkcs8(&self, input: &[u8], is_public: bool) -> Vec<u8> {
        let mut builder = DerBuilder::new();
        builder.begin(DerType::Sequence);
        {
            if !is_public {
                builder.append_integer_from_u8(0);
            }

            builder.begin(DerType::Sequence);
            {
                builder.append_object_identifier(&OID_RSASSA_PSS);
                builder.begin(DerType::Sequence);
                {
                    builder.begin(DerType::Other(DerClass::ContextSpecific, 0));
                    {
                        builder.begin(DerType::Sequence);
                        {
                            builder.append_object_identifier(self.digest());
                        }
                        builder.end();
                    }
                    builder.end();

                    builder.begin(DerType::Other(DerClass::ContextSpecific, 1));
                    {
                        builder.begin(DerType::Sequence);
                        {
                            builder.append_object_identifier(&OID_MGF1);
                            builder.begin(DerType::Sequence);
                            {
                                builder.append_object_identifier(self.digest());
                            }
                            builder.end();
                        }
                        builder.end();
                    }
                    builder.end();

                    builder.begin(DerType::Other(DerClass::ContextSpecific, 2));
                    {
                        builder.append_integer_from_u8(self.salt_len());
                    }
                    builder.end();
                }
                builder.end();
            }
            builder.end();

            if is_public {
                builder.append_bit_string_from_slice(input, 0);
            } else {
                builder.append_octed_string_from_slice(input);
            }
        }
        builder.end();

        builder.build()
    }
}

impl JwsAlgorithm for RsaPssJwsAlgorithm {
    fn name(&self) -> &str {
        match self {
            Self::PS256 => "PS256",
            Self::PS384 => "PS384",
            Self::PS512 => "PS512",
        }
    }
}

pub struct RsaPssJwsSigner<'a> {
    algorithm: &'a RsaPssJwsAlgorithm,
    private_key: PKey<Private>,
}

impl<'a> JwsSigner<RsaPssJwsAlgorithm> for RsaPssJwsSigner<'a> {
    fn algorithm(&self) -> &RsaPssJwsAlgorithm {
        &self.algorithm
    }

    fn sign(&self, message: &mut dyn Read) -> Result<Vec<u8>, JoseError> {
        (|| -> anyhow::Result<Vec<u8>> {
            let message_digest = match self.algorithm {
                RsaPssJwsAlgorithm::PS256 => MessageDigest::sha256(),
                RsaPssJwsAlgorithm::PS384 => MessageDigest::sha384(),
                RsaPssJwsAlgorithm::PS512 => MessageDigest::sha512(),
            };

            let mut signer = Signer::new(message_digest, &self.private_key)?;

            let mut buf = [0; 1024];
            loop {
                match message.read(&mut buf)? {
                    0 => break,
                    n => signer.update(&buf[..n])?,
                }
            }

            let signature = signer.sign_to_vec()?;
            Ok(signature)
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }
}

pub struct RsaPssJwsVerifier<'a> {
    algorithm: &'a RsaPssJwsAlgorithm,
    public_key: PKey<Public>,
}

impl<'a> JwsVerifier<RsaPssJwsAlgorithm> for RsaPssJwsVerifier<'a> {
    fn algorithm(&self) -> &RsaPssJwsAlgorithm {
        &self.algorithm
    }

    fn verify(&self, message: &mut dyn Read, signature: &[u8]) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            let message_digest = match self.algorithm {
                RsaPssJwsAlgorithm::PS256 => MessageDigest::sha256(),
                RsaPssJwsAlgorithm::PS384 => MessageDigest::sha384(),
                RsaPssJwsAlgorithm::PS512 => MessageDigest::sha512(),
            };

            let mut verifier = Verifier::new(message_digest, &self.public_key)?;

            let mut buf = [0; 1024];
            loop {
                match message.read(&mut buf)? {
                    0 => break,
                    n => verifier.update(&buf[..n])?,
                }
            }

            verifier.verify(signature)?;
            Ok(())
        })()
        .map_err(|err| JoseError::InvalidSignature(err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use anyhow::Result;
    use std::fs::File;
    use std::io::{Cursor, Read};
    use std::path::PathBuf;

    #[test]
    fn sign_and_verify_rsspss_jwt() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsaPssJwsAlgorithm::PS256,
            RsaPssJwsAlgorithm::PS384,
            RsaPssJwsAlgorithm::PS512,
        ] {
            let private_key = load_file("jwk/RSA_private.jwk")?;
            let public_key = load_file("jwk/RSA_public.jwk")?;

            let signer = alg.signer_from_jwk(&private_key)?;
            let signature = signer.sign(&mut Cursor::new(input))?;

            let verifier = alg.verifier_from_jwk(&public_key)?;
            verifier.verify(&mut Cursor::new(input), &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsspss_pkcs8_pem() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsaPssJwsAlgorithm::PS256,
            RsaPssJwsAlgorithm::PS384,
            RsaPssJwsAlgorithm::PS512,
        ] {
            let private_key = load_file(match alg {
                RsaPssJwsAlgorithm::PS256 => "pem/RSA-PSS_2048bit_SHA256_pkcs8_private.pem",
                RsaPssJwsAlgorithm::PS384 => "pem/RSA-PSS_2048bit_SHA384_pkcs8_private.pem",
                RsaPssJwsAlgorithm::PS512 => "pem/RSA-PSS_2048bit_SHA512_pkcs8_private.pem",
            })?;
            let public_key = load_file(match alg {
                RsaPssJwsAlgorithm::PS256 => "pem/RSA-PSS_2048bit_SHA256_pkcs8_public.pem",
                RsaPssJwsAlgorithm::PS384 => "pem/RSA-PSS_2048bit_SHA384_pkcs8_public.pem",
                RsaPssJwsAlgorithm::PS512 => "pem/RSA-PSS_2048bit_SHA512_pkcs8_public.pem",
            })?;

            let signer = alg.signer_from_pem(&private_key)?;
            let signature = signer.sign(&mut Cursor::new(input))?;

            let verifier = alg.verifier_from_pem(&public_key)?;
            verifier.verify(&mut Cursor::new(input), &signature)?;
        }

        Ok(())
    }

    #[test]
    fn sign_and_verify_rsspss_pkcs8_der() -> Result<()> {
        let input = b"abcde12345";

        for alg in &[
            RsaPssJwsAlgorithm::PS256,
            RsaPssJwsAlgorithm::PS384,
            RsaPssJwsAlgorithm::PS512,
        ] {
            let private_key = load_file(match alg {
                RsaPssJwsAlgorithm::PS256 => "der/RSA-PSS_2048bit_SHA256_pkcs8_private.der",
                RsaPssJwsAlgorithm::PS384 => "der/RSA-PSS_2048bit_SHA384_pkcs8_private.der",
                RsaPssJwsAlgorithm::PS512 => "der/RSA-PSS_2048bit_SHA512_pkcs8_private.der",
            })?;
            let public_key = load_file(match alg {
                RsaPssJwsAlgorithm::PS256 => "der/RSA-PSS_2048bit_SHA256_pkcs8_public.der",
                RsaPssJwsAlgorithm::PS384 => "der/RSA-PSS_2048bit_SHA384_pkcs8_public.der",
                RsaPssJwsAlgorithm::PS512 => "der/RSA-PSS_2048bit_SHA512_pkcs8_public.der",
            })?;

            let signer = alg.signer_from_der(&private_key)?;
            let signature = signer.sign(&mut Cursor::new(input))?;

            let verifier = alg.verifier_from_der(&public_key)?;
            verifier.verify(&mut Cursor::new(input), &signature)?;
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

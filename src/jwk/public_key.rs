use std::fmt::Debug;

use crate::jwk::Jwk;

#[cfg(feature = "openssl")]
use crate::{util, Value};

/// Common encodings supported by a public key.
pub trait PublicKey: Debug + Send + Sync {
    /// Encode the public key as DER.
    fn to_der_public_key(&self) -> Vec<u8>;

    /// Encode the public key as PEM.
    fn to_pem_public_key(&self) -> Vec<u8>;

    /// Encode the public key as a public JWK.
    fn to_jwk_public_key(&self) -> Jwk;

    /// Encode the public key as a public JWK.
    fn to_jwk(&self) -> Jwk {
        self.to_jwk_public_key()
    }
}

#[cfg(feature = "openssl")]
impl PublicKey for openssl::pkey::PKey<openssl::pkey::Public> {
    fn to_der_public_key(&self) -> Vec<u8> {
        self.public_key_to_der().unwrap()
    }

    fn to_pem_public_key(&self) -> Vec<u8> {
        self.public_key_to_pem().unwrap()
    }

    fn to_jwk_public_key(&self) -> Jwk {
        use openssl::{bn::BigNumContext, nid::Nid, pkey::Id};

        match self.id() {
            Id::RSA | Id::RSA_PSS => {
                let rsa = self.rsa().unwrap();
                let mut jwk = Jwk::new("RSA");
                jwk.set_parameter(
                    "n",
                    Some(Value::String(util::encode_base64_urlsafe_nopad(
                        rsa.n().to_vec(),
                    ))),
                )
                .unwrap();
                jwk.set_parameter(
                    "e",
                    Some(Value::String(util::encode_base64_urlsafe_nopad(
                        rsa.e().to_vec(),
                    ))),
                )
                .unwrap();
                jwk
            }
            Id::EC => {
                let ec = self.ec_key().unwrap();
                let (curve, coordinate_size) = match ec.group().curve_name() {
                    Some(Nid::X9_62_PRIME256V1) => ("P-256", 32),
                    Some(Nid::SECP384R1) => ("P-384", 48),
                    Some(Nid::SECP521R1) => ("P-521", 66),
                    Some(Nid::SECP256K1) => ("secp256k1", 32),
                    _ => unreachable!("unsupported EC public key curve"),
                };
                let mut x = openssl::bn::BigNum::new().unwrap();
                let mut y = openssl::bn::BigNum::new().unwrap();
                let mut context = BigNumContext::new().unwrap();
                ec.public_key()
                    .affine_coordinates_gfp(ec.group(), &mut x, &mut y, &mut context)
                    .unwrap();

                let pad = |bytes: Vec<u8>| {
                    let mut result = vec![0; coordinate_size - bytes.len()];
                    result.extend(bytes);
                    result
                };
                let mut jwk = Jwk::new("EC");
                jwk.set_parameter("crv", Some(Value::String(curve.to_owned())))
                    .unwrap();
                jwk.set_parameter(
                    "x",
                    Some(Value::String(util::encode_base64_urlsafe_nopad(pad(
                        x.to_vec()
                    )))),
                )
                .unwrap();
                jwk.set_parameter(
                    "y",
                    Some(Value::String(util::encode_base64_urlsafe_nopad(pad(
                        y.to_vec()
                    )))),
                )
                .unwrap();
                jwk
            }
            Id::ED25519 | Id::ED448 | Id::X25519 | Id::X448 => {
                let (curve, signing) = match self.id() {
                    Id::ED25519 => ("Ed25519", true),
                    Id::ED448 => ("Ed448", true),
                    Id::X25519 => ("X25519", false),
                    Id::X448 => ("X448", false),
                    _ => unreachable!(),
                };
                let mut jwk = Jwk::new("OKP");
                jwk.set_parameter("crv", Some(Value::String(curve.to_owned())))
                    .unwrap();
                jwk.set_parameter(
                    "x",
                    Some(Value::String(util::encode_base64_urlsafe_nopad(
                        self.raw_public_key().unwrap(),
                    ))),
                )
                .unwrap();
                if signing {
                    jwk.set_key_use("sig");
                } else {
                    jwk.set_key_use("enc");
                }
                jwk
            }
            _ => unreachable!("unsupported public key algorithm"),
        }
    }
}

#[cfg(all(test, feature = "rustcrypto"))]
mod tests {
    use super::PublicKey;
    use crate::jwk::{
        alg::{
            ec::{EcCurve, EcKeyPair},
            ecx::{EcxCurve, EcxKeyPair},
            ed::{EdCurve, EdKeyPair},
            rsa::RsaKeyPair,
        },
        KeyPair,
    };
    use crate::jws::alg::{
        ecdsa::EcdsaJwsAlgorithm::Es256, eddsa::EddsaJwsAlgorithm::Eddsa,
        rsassa::RsassaJwsAlgorithm::Rs256, rsassa_pss::RsassaPssJwsAlgorithm::Ps256,
    };

    fn assert_public_encoding<T: PublicKey>(public_key: &T, expected_jwk: crate::jwk::Jwk) {
        assert!(!public_key.to_der_public_key().is_empty());
        assert!(!public_key.to_pem_public_key().is_empty());
        assert_eq!(public_key.to_jwk(), expected_jwk);
    }

    #[test]
    fn public_keys_encode_as_jwk() {
        for curve in [
            EcCurve::P256,
            EcCurve::P384,
            EcCurve::P521,
            EcCurve::Secp256k1,
        ] {
            let key_pair = EcKeyPair::generate(curve).unwrap();
            let expected = key_pair.to_jwk_public_key();
            let public_key = key_pair.into_private_key().public_key();
            assert_public_encoding(&public_key, expected);
        }

        for curve in [EdCurve::Ed25519, EdCurve::Ed448] {
            let key_pair = EdKeyPair::generate(curve).unwrap();
            let expected = key_pair.to_jwk_public_key();
            let public_key = key_pair.into_private_key().public_key();
            assert_public_encoding(&public_key, expected);
        }

        for curve in [EcxCurve::X25519, EcxCurve::X448] {
            let key_pair = EcxKeyPair::generate(curve).unwrap();
            let expected = key_pair.to_jwk_public_key();
            let public_key = key_pair.into_private_key().public_key();
            assert_public_encoding(&public_key, expected);
        }

        let key_pair = RsaKeyPair::generate(1024).unwrap();
        let expected = key_pair.to_jwk_public_key();
        let public_key = key_pair.into_private_key().to_public_key();
        assert_public_encoding(&public_key, expected);
    }

    #[test]
    fn jws_verifiers_expose_their_public_key() {
        let mut key_pair = Es256.generate_key_pair().unwrap();
        key_pair.set_key_id(Some("ec-key"));
        let expected = key_pair.to_jwk_public_key();
        let verifier = Es256.verifier_from_jwk(&expected).unwrap();
        assert_public_encoding(&verifier, expected);

        let mut key_pair = Eddsa.generate_key_pair(EdCurve::Ed25519).unwrap();
        key_pair.set_key_id(Some("ed-key"));
        let expected = key_pair.to_jwk_public_key();
        let verifier = Eddsa.verifier_from_jwk(&expected).unwrap();
        assert_public_encoding(&verifier, expected);

        let mut key_pair = Rs256.generate_key_pair(2048).unwrap();
        key_pair.set_key_id(Some("rsa-key"));
        let expected = key_pair.to_jwk_public_key();
        let verifier = Rs256.verifier_from_jwk(&expected).unwrap();
        assert_public_encoding(&verifier, expected);

        let mut key_pair = Ps256.generate_key_pair(2048).unwrap();
        key_pair.set_key_id(Some("pss-key"));
        let expected = key_pair.to_jwk_public_key();
        let verifier = Ps256.verifier_from_jwk(&expected).unwrap();
        assert_public_encoding(&verifier, expected);
    }

    #[cfg(feature = "pqc")]
    #[test]
    fn mldsa_public_keys_and_verifiers_encode_as_jwk() {
        use crate::jwk::alg::ml_dsa::{MlDsa, MlDsaKeyPair};
        use crate::jws::alg::ml_dsa::MldsaJwsAlgorithm::MlDSA44;

        let key_pair = MlDsaKeyPair::generate(MlDsa::MlDsa44).unwrap();
        let expected = key_pair.to_jwk_public_key();
        let public_key = key_pair.into_private_key().public_key();
        assert_public_encoding(&public_key, expected);

        let mut key_pair = MlDSA44.generate_key_pair().unwrap();
        key_pair.set_key_id(Some("mldsa-key"));
        let expected = key_pair.to_jwk_public_key();
        let verifier = MlDSA44.verifier_from_jwk(&expected).unwrap();
        assert_public_encoding(&verifier, expected);
    }
}

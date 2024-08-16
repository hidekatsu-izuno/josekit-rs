
use openssl::rand;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::error::ErrorStack;

use crate::jwk::alg::ec::EcCurve;
use crate::jwk::alg::ecx::EcxCurve;
use crate::jwk::alg::ed::EdCurve;

pub(crate) type RsaPrivateKey = PKey<Private>;
pub(crate) type EcPrivateKey = PKey<Private>;
pub(crate) type EcxPrivateKey = PKey<Private>;
pub(crate) type EdPrivateKey = PKey<Private>;
pub(crate) type CryptoError = ErrorStack;

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut vec = vec![0; len];
    rand::rand_bytes(&mut vec).unwrap();
    vec
}

pub(crate) fn generate_rsa_private_key(bits: u32) -> Result<RsaPrivateKey, CryptoError> {
    let rsa = Rsa::generate(bits)?;
    let private_key = PKey::from_rsa(rsa)?;
    Ok(private_key)
}

pub(crate) fn load_rsa_private_key_from_der(input: impl AsRef<[u8]>) -> Result<RsaPrivateKey, CryptoError> {
    let private_key = PKey::private_key_from_der(input.as_ref())?;
    Ok(private_key)
}

pub(crate) fn generate_ec_private_key(curve: EcCurve) -> Result<EcPrivateKey, CryptoError> {
    let nid = match curve {
        EcCurve::P256 => Nid::X9_62_PRIME256V1,
        EcCurve::P384 => Nid::SECP384R1,
        EcCurve::P521 => Nid::SECP521R1,
        EcCurve::Secp256k1 => Nid::SECP256K1,
    };
    let ec_group = EcGroup::from_curve_name(nid)?;
    let ec_key = EcKey::generate(&ec_group)?;
    let private_key = PKey::from_ec_key(ec_key)?;
    Ok(private_key)
}

pub(crate) fn load_ec_private_key_from_der(input: impl AsRef<[u8]>) -> Result<EcPrivateKey, CryptoError> {
    let private_key = PKey::private_key_from_der(input.as_ref())?;
    Ok(private_key)
}

pub(crate) fn generate_ecx_private_key(curve: EcxCurve) -> Result<EcxPrivateKey, CryptoError> {
    let private_key = match curve {
        EcxCurve::X25519 => PKey::generate_x25519()?,
        EcxCurve::X448 => PKey::generate_x448()?,
    };
    Ok(private_key)
}

pub(crate) fn load_ecx_private_key_from_der(input: impl AsRef<[u8]>) -> Result<EcxPrivateKey, CryptoError> {
    let private_key = PKey::private_key_from_der(input.as_ref())?;
    Ok(private_key)
}

pub(crate) fn generate_ed_private_key(curve: EdCurve) -> Result<EdPrivateKey, CryptoError> {
    let private_key = match curve {
        EdCurve::Ed25519 => PKey::generate_ed25519()?,
        EdCurve::Ed448 => PKey::generate_ed448()?,
    };
    Ok(private_key)
}

pub(crate) fn load_ed_private_key_from_der(input: impl AsRef<[u8]>) -> Result<EdPrivateKey, CryptoError> {
    let private_key = PKey::private_key_from_der(input.as_ref())?;
    Ok(private_key)
}

use rand;
use crypto::rsa::RsaPrivateKey;
use crypto::ec::EcPrivateKey;
use crypto::ecx::EcxPrivateKey;
use crypto::ed::EdPrivateKey;
use crypto::rsa::errors::Error;
use crypto::pkcs8::DecodePrivateKey;

use crate::jwk::alg::ec::EcCurve;
use crate::jwk::alg::ecx::EcxCurve;
use crate::jwk::alg::ed::EdCurve;

pub(crate) type RsaPrivateKey = RsaPrivateKey;
pub(crate) type EcPrivateKey = EcPrivateKey;
pub(crate) type EcxPrivateKey = EcxPrivateKey;
pub(crate) type EdPrivateKey = EdPrivateKey;
pub(crate) type CryptoError = Error;

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut vec = vec![0; len];
    rand::thread_rng().fill_bytes(&mut vec);
    vec
}

pub(crate) fn generate_rsa_private_key(bits: u32) -> Result<RsaPrivateKey, CryptoError> {
    let rand = rand::thread_rng()?;
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    Ok(private_key)
}

pub(crate) fn load_rsa_private_key_from_der(input: impl AsRef<[u8]>) -> Result<RsaPrivateKey, CryptoError> {
    let private_key = RsaPrivateKey::from_pkcs8_der(input.as_ref())?;
    Ok(private_key)
}

pub(crate) fn generate_ec_private_key(curve: EcCurve) -> Result<EcPrivateKey, CryptoError> {
    unimplemented!();
}

pub(crate) fn load_ec_private_key_from_der(input: impl AsRef<[u8]>) -> Result<EcPrivateKey, CryptoError> {
    let private_key = EcPrivateKey::from_pkcs8_der(input.as_ref())?;
    Ok(private_key)
}

pub(crate) fn generate_ecx_private_key(curve: EcxCurve) -> Result<EcxPrivateKey, CryptoError> {
    unimplemented!();
}

pub(crate) fn load_ecx_private_key_from_der(input: impl AsRef<[u8]>) -> Result<EcxPrivateKey, CryptoError> {
    let private_key = EcxPrivateKey::from_pkcs8_der(input.as_ref())?;
    Ok(private_key)
}

pub(crate) fn generate_ed_private_key(curve: EdCurve) -> Result<EdPrivateKey, CryptoError> {
    unimplemented!();
}

pub(crate) fn load_ed_private_key_from_der(input: impl AsRef<[u8]>) -> Result<EdPrivateKey, CryptoError> {
    let private_key = EdPrivateKey::from_pkcs8_der(input.as_ref())?;
    Ok(private_key)
}

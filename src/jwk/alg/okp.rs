use anyhow::{bail, Context};
use pkcs8::der::{asn1::OctetStringRef, zeroize::Zeroizing, Decode};
use pkcs8::{ObjectIdentifier, PrivateKeyInfoRef, SubjectPublicKeyInfoRef};

use crate::util;

#[cfg(feature = "ed448-goldilocks-plus")]
pub(crate) const ED448_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.113");
#[cfg(feature = "x448-goldilocks-plus")]
pub(crate) const X448_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.111");

#[cfg(feature = "ed25519-dalek")]
pub(crate) const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

#[cfg(feature = "x25519-dalek")]
pub(crate) const X25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");

pub(crate) fn private_key_bytes(der: &[u8], oid: ObjectIdentifier) -> anyhow::Result<&[u8]> {
    let key = PrivateKeyInfoRef::from_der(der)?;
    if key.algorithm.oid != oid || key.algorithm.parameters.is_some() {
        bail!("Invalid OKP private key algorithm identifier.");
    }
    // RFC 8410 wraps the raw private key in an inner OCTET STRING.
    Ok(<&OctetStringRef>::from_der(key.private_key.as_bytes())?.as_bytes())
}

pub(crate) fn public_key_bytes(der: &[u8], oid: ObjectIdentifier) -> anyhow::Result<&[u8]> {
    let key = SubjectPublicKeyInfoRef::from_der(der)?;
    if key.algorithm.oid != oid || key.algorithm.parameters.is_some() {
        bail!("Invalid OKP public key algorithm identifier.");
    }
    key.subject_public_key
        .as_bytes()
        .context("Invalid OKP public key bit string.")
}

pub(crate) fn random_secret<const N: usize>() -> anyhow::Result<Zeroizing<[u8; N]>> {
    let mut secret = Zeroizing::new([0; N]);
    util::fill_random_bytes!(secret.as_mut())?;
    Ok(secret)
}

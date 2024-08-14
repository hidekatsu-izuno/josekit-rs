use openssl::hash::MessageDigest;

use crate::util::hash_algorithm::HashAlgorithm;

#[cfg(feature="no_ffi")]
include!("crypto/rust_crypto.rs");

#[cfg(not(feature="no_ffi"))]
include!("crypto/openssl.rs");

pub(crate) fn message_digest(alg: &HashAlgorithm) -> MessageDigest {
    match alg {
        HashAlgorithm::Sha1 => MessageDigest::sha1(),
        HashAlgorithm::Sha256 => MessageDigest::sha256(),
        HashAlgorithm::Sha384 => MessageDigest::sha384(),
        HashAlgorithm::Sha512 => MessageDigest::sha512(),
    }
}
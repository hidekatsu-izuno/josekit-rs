//! # josekit
//!
//! `josekit` is a JOSE (Javascript Object Signing and Encryption: JWT, JWS, JWE, JWA, JWK) library.

pub mod jwe;
pub mod jwk;
pub mod jws;
pub mod jwt;
pub mod util;

mod hash_algorithm;
mod jose_error;
mod jose_header;

pub use crate::hash_algorithm::HashAlgorithm;
pub use crate::jose_error::JoseError;
pub use crate::jose_header::JoseHeader;

pub use serde_json::{Map, Number, Value};

pub use HashAlgorithm::Sha1 as SHA_1;
pub use HashAlgorithm::Sha256 as SHA_256;
pub use HashAlgorithm::Sha384 as SHA_384;
pub use HashAlgorithm::Sha512 as SHA_512;

#[cfg(doctest)]
use doc_comment::doctest;

#[cfg(doctest)]
doctest!("../README.md");

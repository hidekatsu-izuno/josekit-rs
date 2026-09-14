//! # josekit
//!
//! `josekit` is a JOSE (Javascript Object Signing and Encryption: JWT, JWS, JWE, JWA, JWK) library.

pub mod jwe;
pub mod jwk;
pub mod jws;
pub mod jwt;
pub mod util;

mod jose_error;
mod jose_header;

pub use crate::jose_error::JoseError;
pub use crate::jose_header::JoseHeader;

pub use serde_json::{Map, Number, Value};

/// Re-exported so that the `kapun_*_provider!` macros resolve their paths through `$crate`.
#[cfg(feature = "kapun-provider")]
pub use kapun_crypto_provider;

#[cfg(doctest)]
use doc_comment::doctest;

#[cfg(doctest)]
doctest!("../README.md");

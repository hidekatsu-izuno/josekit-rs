//! # josekit
//!
//! `josekit` is a JOSE (Javascript Object Signing and Encryption: JWT, JWS, JWE, JWA, JWK) library.

#[cfg(all(
    not(feature = "openssl"),
    not(feature = "aws-lc-rs"),
    not(all(
        feature = "aes-cbc-hmac-rustcrypto",
        feature = "aes-gcm-rustcrypto",
        feature = "aes-kw-rustcrypto",
        feature = "ec-rustcrypto",
        feature = "ed25519-dalek",
        feature = "ed448-goldilocks-plus",
        feature = "hmac-rustcrypto",
        feature = "pbkdf2-rustcrypto",
        feature = "rsa-rustcrypto",
        feature = "x25519-dalek",
        feature = "x448-goldilocks-plus",
    ))
))]
compile_error!("Enable the `openssl` feature or select a Rust backend for every algorithm.");

pub mod jwe;
pub mod jwk;
pub mod jws;
pub mod jwt;
pub mod util;

#[cfg(feature = "aws-lc-rs")]
mod aws_lc;
mod jose_error;
mod jose_header;

pub use crate::jose_error::JoseError;
pub use crate::jose_header::JoseHeader;

pub use serde_json::{Map, Number, Value};

#[cfg(doctest)]
use doc_comment::doctest;

#[cfg(doctest)]
doctest!("../README.md");

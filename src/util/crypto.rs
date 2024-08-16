#[cfg(feature = "no_ffi")]
include!("crypto/rust_crypto.rs");

#[cfg(not(feature = "no_ffi"))]
include!("crypto/openssl.rs");

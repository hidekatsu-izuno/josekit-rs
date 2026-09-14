//! Glue between josekit's JWS signers/verifiers and the `kapun-crypto-provider` traits.
//!
//! The macros are only defined when the `kapun-provider` feature is enabled, so every
//! invocation has to be feature gated as well. They expand to fully qualified paths
//! only, which keeps them free of `use` statements that would collide with the caller's
//! imports (e.g. `openssl::sign::Signer`) or with each other when both macros are used
//! in the same module.

/// Implements the kapun signing traits for a josekit `JwsSigner` holding a `private_key`.
#[macro_export]
macro_rules! kapun_signing_provider {
    ($alg:ty) => {
        impl $crate::kapun_crypto_provider::Signer for $alg {}

        impl $crate::kapun_crypto_provider::Signing for $alg {
            fn kapun_sign(
                &self,
                data: Vec<u8>,
            ) -> Result<Vec<u8>, $crate::kapun_crypto_provider::SigningProblem> {
                $crate::jws::JwsSigner::sign(self, &data)
                    .map_err(|_| $crate::kapun_crypto_provider::SigningProblem::SigningFailed)
            }

            fn kapun_sign_hash(
                &self,
                hash: Vec<u8>,
            ) -> Result<Vec<u8>, $crate::kapun_crypto_provider::SigningProblem> {
                $crate::jws::JwsSigner::sign_prehashed(self, &hash)
                    .map_err(|_| $crate::kapun_crypto_provider::SigningProblem::SigningFailed)
            }
        }

        impl $crate::kapun_crypto_provider::KeyEncoding for $alg {
            fn kapun_private_jwk(&self) -> Option<String> {
                self.private_key.ec_key_jwk().ok()
            }

            fn kapun_public_jwk(&self) -> Option<String> {
                self.private_key.public_key().ec_key_jwk().ok()
            }

            fn kapun_private_pkcs8_der(&self) -> Option<Vec<u8>> {
                self.private_key.ec_key_der().ok()
            }

            fn kapun_private_pkcs8_pem(&self) -> Option<String> {
                self.private_key.ec_key_pem().ok()
            }

            fn kapun_public_spki_der(&self) -> Option<Vec<u8>> {
                self.private_key.public_key().ec_key_der().ok()
            }

            fn kapun_public_spki_pem(&self) -> Option<String> {
                self.private_key.public_key().ec_key_pem().ok()
            }
        }

        impl $crate::kapun_crypto_provider::Metadata for $alg {
            fn kapun_jose_alg(&self) -> Option<String> {
                Some($crate::jws::JwsAlgorithm::name(&self.algorithm).to_string())
            }

            fn kapun_oid(&self) -> Option<Vec<u8>> {
                None
            }
        }
    };
}

/// Implements the kapun verifying traits for a josekit `JwsVerifier` holding a `public_key`.
#[macro_export]
macro_rules! kapun_verifying_provider {
    ($alg:ty) => {
        impl $crate::kapun_crypto_provider::Verifier for $alg {}

        impl $crate::kapun_crypto_provider::Verifying for $alg {
            fn kapun_verify(
                &self,
                data: Vec<u8>,
                signature: Vec<u8>,
            ) -> Result<(), $crate::kapun_crypto_provider::VerificationProblem> {
                $crate::jws::JwsVerifier::verify(self, &data, &signature).map_err(|_| {
                    $crate::kapun_crypto_provider::VerificationProblem::SignatureInvalid
                })
            }

            fn kapun_verify_hash(
                &self,
                hash: Vec<u8>,
                signature: Vec<u8>,
            ) -> Result<(), $crate::kapun_crypto_provider::VerificationProblem> {
                $crate::jws::JwsVerifier::verify_prehashed(self, &hash, &signature).map_err(|_| {
                    $crate::kapun_crypto_provider::VerificationProblem::SignatureInvalid
                })
            }
        }

        impl $crate::kapun_crypto_provider::KeyEncoding for $alg {
            fn kapun_public_jwk(&self) -> Option<String> {
                self.public_key.ec_key_jwk().ok()
            }

            fn kapun_public_spki_der(&self) -> Option<Vec<u8>> {
                self.public_key.ec_key_der().ok()
            }

            fn kapun_public_spki_pem(&self) -> Option<String> {
                self.public_key.ec_key_pem().ok()
            }
        }

        impl $crate::kapun_crypto_provider::Metadata for $alg {
            fn kapun_jose_alg(&self) -> Option<String> {
                Some($crate::jws::JwsAlgorithm::name(&self.algorithm).to_string())
            }

            fn kapun_oid(&self) -> Option<Vec<u8>> {
                None
            }
        }
    };
}

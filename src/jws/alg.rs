pub mod hmac;
pub mod rsassa;
pub mod rsassa_pss;
pub mod ecdsa;
pub mod eddsa;

pub use crate::jws::alg::hmac::HmacJwsAlgorithm::HS256;
pub use crate::jws::alg::hmac::HmacJwsAlgorithm::HS384;
pub use crate::jws::alg::hmac::HmacJwsAlgorithm::HS512;

pub use crate::jws::alg::rsassa::RsassaJwsAlgorithm::RS256;
pub use crate::jws::alg::rsassa::RsassaJwsAlgorithm::RS384;
pub use crate::jws::alg::rsassa::RsassaJwsAlgorithm::RS512;

pub use crate::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm::PS256;
pub use crate::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm::PS384;
pub use crate::jws::alg::rsassa_pss::RsassaPssJwsAlgorithm::PS512;

pub use crate::jws::alg::ecdsa::EcdsaJwsAlgorithm::ES256;
pub use crate::jws::alg::ecdsa::EcdsaJwsAlgorithm::ES256K;
pub use crate::jws::alg::ecdsa::EcdsaJwsAlgorithm::ES384;
pub use crate::jws::alg::ecdsa::EcdsaJwsAlgorithm::ES512;

pub use crate::jws::alg::eddsa::EddsaJwsAlgorithm::EdDSA;

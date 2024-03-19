use std::borrow::Cow;
use std::fmt::Debug;

use crate::jwe::{JweContentEncryption, JweHeader};
use crate::JoseError;

/// Represent a algorithm of JWE alg header claim.
pub trait JweAlgorithm: Debug + Send + Sync {
    /// Return the "alg" (algorithm) header parameter value of JWE.
    fn name(&self) -> &str;

    fn box_clone(&self) -> Box<dyn JweAlgorithm>;
}

impl PartialEq for Box<dyn JweAlgorithm> {
    fn eq(&self, other: &Self) -> bool {
        self == other
    }
}

impl Eq for Box<dyn JweAlgorithm> {}

impl Clone for Box<dyn JweAlgorithm> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

pub trait JweEncrypter: Debug + Send + Sync {
    /// Return the source algorithm instance.
    fn algorithm(&self) -> &dyn JweAlgorithm;

    /// Return the source key ID.
    /// The default value is a value of kid parameter in JWK.
    fn key_id(&self) -> Option<&str>;

    /// Compute a content encryption key.
    ///
    /// # Arguments
    ///
    /// * `cencryption` - The content encryption method.
    /// * `in_header` - the input header
    /// * `out_header` - the output header
    fn compute_content_encryption_key(
        &self,
        cencryption: &dyn JweContentEncryption,
        in_header: &JweHeader,
        out_header: &mut JweHeader,
    ) -> Result<Option<Cow<[u8]>>, JoseError>;

    /// Return a encypted key.
    ///
    /// # Arguments
    ///
    /// * `key` - The content encryption key
    /// * `in_header` - the input header
    /// * `out_header` - the output header
    fn encrypt(
        &self,
        key: &[u8],
        in_header: &JweHeader,
        out_header: &mut JweHeader,
    ) -> Result<Option<Vec<u8>>, JoseError>;

    fn box_clone(&self) -> Box<dyn JweEncrypter>;
}

impl Clone for Box<dyn JweEncrypter> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

pub trait JweDecrypter: Debug + Send + Sync {
    /// Return the source algorithm instance.
    fn algorithm(&self) -> &dyn JweAlgorithm;

    /// Return the source key ID.
    /// The default value is a value of kid parameter in JWK.
    fn key_id(&self) -> Option<&str>;

    /// Return a decrypted key.
    ///
    /// # Arguments
    ///
    /// * `encrypted_key` - The encrypted key.
    /// * `cencryption` - The content encryption method.
    /// * `header` - The header
    fn decrypt(
        &self,
        encrypted_key: Option<&[u8]>,
        cencryption: &dyn JweContentEncryption,
        header: &JweHeader,
    ) -> Result<Cow<[u8]>, JoseError>;

    fn box_clone(&self) -> Box<dyn JweDecrypter>;
}

impl Clone for Box<dyn JweDecrypter> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

#[async_trait::async_trait]
#[cfg(feature = "async")]
pub trait JweDecrypterAsync: Debug + Send + Sync {
    /// Return the source algorithm instance.
    fn algorithm(&self) -> &dyn JweAlgorithm;

    /// Return the source key ID.
    /// The default value is a value of kid parameter in JWK.
    fn key_id(&self) -> Option<&str>;

    /// Return a decrypted key.
    ///
    /// This function is async to allow IO, eg. network call
    /// to decrypt the key using external key management services
    /// like Amazon KMS.
    ///
    /// # Arguments
    ///
    /// * `encrypted_key` - The encrypted key.
    /// * `cencryption` - The content encryption method.
    /// * `header` - The header
    async fn decrypt(
        &self,
        encrypted_key: Option<&[u8]>,
        cencryption: &dyn JweContentEncryption,
        header: &JweHeader,
    ) -> Result<Cow<[u8]>, JoseError>;
}

#[cfg(test)]
#[cfg(feature = "async")]
mod test_async {
    use openssl::hash::MessageDigest;

    use crate::{
        jwe::{self, alg::rsaes::RsaesJweAlgorithm, JweContext, JweHeader},
        jwk::alg::rsa::RsaKeyPair,
    };

    use super::JweDecrypterAsync;

    const PLAINTEXT: &str = "The quick brown fox jumps over the lazy dog";
    const PRIVATE_KEY: &str = include_str!("../../data/pem/RSA_2048bit_private.pem");
    const PUBLIC_KEY: &str = include_str!("../../data/pem/RSA_2048bit_public.pem");
    const KEY_ID: &str = "32b9e1af-fcb3-49d5-a027-c88746cfe193";

    #[test]
    fn sync_test() {
        let ctx = JweContext::new();
        let jwe = create_jwe(&ctx);

        // decrypt - sync
        let decrypter = RsaesJweAlgorithm::RsaOaep256
            .decrypter_from_pem(PRIVATE_KEY)
            .expect("create decrypter");

        let (decrypted_payload, _decrypted_header) = ctx
            .deserialize_compact(jwe.as_bytes(), &decrypter)
            .expect("deserialize_compact");

        assert_eq!(PLAINTEXT.as_bytes(), &decrypted_payload);
    }

    #[tokio::test]
    async fn async_test() {
        let ctx = JweContext::new();
        let jwe = create_jwe(&ctx);

        // decrypt - using async

        let decrypter = RsaesJweAlgorithmUsingKms::new();

        let (decrypted_payload, _decrypted_header) = ctx
            .deserialize_compact_async(jwe.as_bytes(), &decrypter)
            .await
            .expect("deserialize_compact");

        assert_eq!(PLAINTEXT.as_bytes(), &decrypted_payload);
    }

    #[derive(Debug)]
    struct RsaesJweAlgorithmUsingKms;

    impl RsaesJweAlgorithmUsingKms {
        fn new() -> Self {
            Self
        }
    }

    #[async_trait::async_trait]
    impl JweDecrypterAsync for RsaesJweAlgorithmUsingKms {
        fn algorithm(&self) -> &dyn super::JweAlgorithm {
            &RsaesJweAlgorithm::RsaOaep256
        }

        fn key_id(&self) -> Option<&str> {
            Some(KEY_ID)
        }

        async fn decrypt(
            &self,
            encrypted_key: Option<&[u8]>,
            _cencryption: &dyn super::JweContentEncryption,
            _header: &JweHeader,
        ) -> Result<std::borrow::Cow<[u8]>, crate::JoseError> {
            //
            // Imagine making a network call to decrypt the key using KMS
            //
            let encrypted_key = encrypted_key.unwrap();

            let pkey = RsaKeyPair::from_pem(PRIVATE_KEY)
                .expect("from_pem")
                .into_private_key();

            let key = jwe::alg::rsaes::openssl_rsa_oaep::pkey_private_decrypt(
                &pkey,
                &encrypted_key,
                MessageDigest::sha256(),
            )
            .expect("pkey_private_decrypt");

            Ok(std::borrow::Cow::Owned(key))
        }
    }

    fn create_jwe(ctx: &JweContext) -> String {
        let encrypter = RsaesJweAlgorithm::RsaOaep256
            .encrypter_from_pem(PUBLIC_KEY)
            .expect("create encrypter");

        let mut header = JweHeader::new();
        header.set_content_encryption("A256GCM");
        header.set_key_id(KEY_ID);

        let jwe = ctx
            .serialize_compact(PLAINTEXT.as_bytes(), &header, &encrypter)
            .expect("serialize_compact");
        jwe
    }
}

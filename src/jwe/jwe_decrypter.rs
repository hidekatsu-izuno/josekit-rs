use std::borrow::Cow;
use std::fmt::Debug;

use crate::jose::JoseError;
use crate::jwe::{JweHeader, JweAlgorithm};

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
    /// * `header` - The header
    /// * `encrypted_key` - The encrypted key.
    /// * `key_len` - the length of the content encryption key
    fn decrypt(
        &self,
        header: &JweHeader,
        encrypted_key: Option<&[u8]>,
        key_len: usize,
    ) -> Result<Cow<[u8]>, JoseError>;

    fn box_clone(&self) -> Box<dyn JweDecrypter>;
}

impl Clone for Box<dyn JweDecrypter> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

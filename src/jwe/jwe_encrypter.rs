use std::borrow::Cow;
use std::fmt::Debug;

use crate::jose::JoseError;
use crate::jwe::{JweHeader, JweAlgorithm};

pub trait JweEncrypter: Debug + Send + Sync {
    /// Return the source algorithm instance.
    fn algorithm(&self) -> &dyn JweAlgorithm;

    /// Return the source key ID.
    /// The default value is a value of kid parameter in JWK.
    fn key_id(&self) -> Option<&str>;

    /// Return a content encryption key and encypted data.
    /// # Arguments
    ///
    /// * `header` - the header
    /// * `key_len` - the length of the content encryption key
    fn encrypt(
        &self,
        header: &mut JweHeader,
        key_len: usize,
    ) -> Result<(Cow<[u8]>, Option<Vec<u8>>), JoseError>;

    fn box_clone(&self) -> Box<dyn JweEncrypter>;
}

impl Clone for Box<dyn JweEncrypter> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

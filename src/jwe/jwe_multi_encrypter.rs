use anyhow::bail;

use crate::jwe::{JweHeader, JweEncrypter};
use crate::{JoseError, JoseHeader};

#[derive(Debug)]
pub struct JweMultiEncrypter<'a> {
    encrypters: Vec<(
        Option<&'a JweHeader>,
        Option<&'a JweHeader>,
        &'a dyn JweEncrypter,
    )>,
}

impl<'a> JweMultiEncrypter<'a> {
    pub fn new() -> Self {
        JweMultiEncrypter {
            encrypters: Vec::new(),
        }
    }

    pub fn encrypters(
        &self,
    ) -> &Vec<(
        Option<&'a JweHeader>,
        Option<&'a JweHeader>,
        &'a dyn JweEncrypter,
    )> {
        &self.encrypters
    }

    pub fn add_encrypter(
        &mut self,
        protected: Option<&'a JweHeader>,
        header: Option<&'a JweHeader>,
        encrypter: &'a dyn JweEncrypter,
    ) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            if let Some(protected) = protected {
                if let Some(header) = header {
                    let protected_map = protected.claims_set();
                    let header_map = header.claims_set();
                    for key in header_map.keys() {
                        if protected_map.contains_key(key) {
                            bail!("A duplicate key exists: {}", key);
                        }
                    }
                }
            }
            
            self.encrypters.push((protected, header, encrypter));

            Ok(())
        })()
        .map_err(|err| JoseError::InvalidJweFormat(err))
    }
}
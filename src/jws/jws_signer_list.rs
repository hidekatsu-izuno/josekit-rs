use std::slice;

use anyhow::bail;

use crate::jws::{JwsHeader, JwsSigner};
use crate::{JoseError, JoseHeader};

#[derive(Debug)]
pub struct JwsSignerList<'a> {
    list: Vec<(
        Option<&'a JwsHeader>,
        Option<&'a JwsHeader>,
        &'a dyn JwsSigner,
    )>,
}

impl<'a> JwsSignerList<'a> {
    pub fn new() -> Self {
        Self {
            list: Vec::new(),
        }
    }

    pub fn iter(&self) -> slice::Iter<'_, (
        Option<&'a JwsHeader>,
        Option<&'a JwsHeader>,
        &'a dyn JwsSigner,
    )> {
        self.list.as_slice().iter()
    }

    pub fn push_signer(
        &mut self,
        protected: Option<&'a JwsHeader>,
        header: Option<&'a JwsHeader>,
        signer: &'a dyn JwsSigner,
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

            self.list.push((protected, header, signer));

            Ok(())
        })()
        .map_err(|err| JoseError::InvalidJwsFormat(err))
    }
}

use anyhow::bail;

use crate::jose::{JoseError, JoseHeader};
use crate::jws::{JwsHeader, JwsSigner};
pub struct JwsMultiSigner<'a> {
    signers: Vec<(
        Option<&'a JwsHeader>,
        Option<&'a JwsHeader>,
        &'a dyn JwsSigner,
    )>,
}

impl<'a> JwsMultiSigner<'a> {
    pub fn new() -> Self {
        JwsMultiSigner {
            signers: Vec::new(),
        }
    }

    pub fn signers(
        &self,
    ) -> &Vec<(
        Option<&'a JwsHeader>,
        Option<&'a JwsHeader>,
        &'a dyn JwsSigner,
    )> {
        &self.signers
    }

    pub fn add_signer(
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

            self.signers.push((protected, header, signer));

            Ok(())
        })()
        .map_err(|err| JoseError::InvalidJwsFormat(err))
    }
}

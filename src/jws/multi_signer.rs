use anyhow::bail;
use serde_json::{Map, Value};

use crate::jose::{JoseError, JoseHeader};
use crate::jws::{JwsHeader, JwsSigner};

pub struct JwsMultiSigner<'a> {
    signers: Vec<(Box<dyn JwsSigner + 'a>, Map<String, Value>)>,
}

impl<'a> JwsMultiSigner<'a> {
    pub fn new() -> Self {
        JwsMultiSigner {
            signers: Vec::new(),
        }
    }

    pub fn add_signer(
        &mut self,
        signer: impl JwsSigner + 'a,
        protected: Option<&JwsHeader>,
        header: Option<&JwsHeader>,
    ) -> Result<(), JoseError> {
        (|| -> anyhow::Result<()> {
            let mut sig_item = Map::new();

            let mut protected_map;
            let protected_base64;
            if let Some(val) = protected {
                protected_map = val.claims_set().clone();
                protected_map.insert(
                    "alg".to_string(),
                    Value::String(signer.algorithm().name().to_string()),
                );

                let json = serde_json::to_string(&protected_map).unwrap();
                protected_base64 = base64::encode_config(json, base64::URL_SAFE_NO_PAD);
                sig_item.insert("protected".to_string(), Value::String(protected_base64));
            } else {
                protected_map = Map::new();
                protected_map.insert(
                    "alg".to_string(),
                    Value::String(signer.algorithm().name().to_string()),
                );

                let json = serde_json::to_string(&protected_map).unwrap();
                protected_base64 = base64::encode_config(json, base64::URL_SAFE_NO_PAD);
                sig_item.insert("protected".to_string(), Value::String(protected_base64));
            }

            if let Some(val) = header {
                let map = val.claims_set().clone();
                for key in map.keys() {
                    if protected_map.contains_key(key) {
                        bail!("Duplicate key exists: {}", key);
                    }
                }

                if map.len() > 0 {
                    sig_item.insert("header".to_string(), Value::Object(map));
                }
            }

            self.signers.push((Box::new(signer), sig_item));

            Ok(())
        })()
        .map_err(|err| match err.downcast::<JoseError>() {
            Ok(err) => err,
            Err(err) => JoseError::InvalidJwsFormat(err),
        })
    }

    pub fn serialize_json(&self, payload: &[u8]) -> Result<String, JoseError> {
        let payload = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);

        let mut sig_vec = Vec::new();
        for (signer, sig_item) in &self.signers {
            let protected = sig_item.get("protected").unwrap();
            let message = format!("{}.{}", protected, payload);
            let signature = signer.sign(message.as_bytes())?;
            let signature = base64::encode_config(&signature, base64::URL_SAFE_NO_PAD);

            let mut sig_item = sig_item.clone();
            sig_item.insert("signature".to_string(), Value::String(signature));
            sig_vec.push(Value::Object(sig_item));
        }

        let signatures = serde_json::to_string(&sig_vec).unwrap();
        let result = format!(
            "{{\"signatures\":{},\"payload\":\"{}\"}}",
            &signatures, &payload
        );

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwk::KeyPair;
    use crate::jws::{ES256, RS256};

    #[test]
    fn sign_multpile() -> anyhow::Result<()> {
        let payload = b"abcde012345";

        let mut multi_signer = JwsMultiSigner::new();

        let keypair1 = RS256.generate_keypair(2048)?;
        let signer1 = RS256.signer_from_der(keypair1.to_der_private_key())?;
        let protected1 = JwsHeader::new();
        let header1 = JwsHeader::new();
        multi_signer.add_signer(signer1, Some(&protected1), Some(&header1))?;

        let keypair2 = ES256.generate_keypair()?;
        let signer2 = ES256.signer_from_der(keypair2.to_der_private_key())?;
        let protected2 = JwsHeader::new();
        let mut header2 = JwsHeader::new();
        header2.set_key_id("key_id");
        multi_signer.add_signer(signer2, Some(&protected2), Some(&header2))?;

        println!("{}", multi_signer.serialize_json(payload)?);

        Ok(())
    }
}

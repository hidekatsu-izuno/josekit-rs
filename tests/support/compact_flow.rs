use std::borrow::Cow;
use std::io;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use josekit::jwe::{
    JweAlgorithm, JweCompression, JweContentEncryption, JweContext, JweDecrypter, JweHeader, A128KW,
};
use josekit::jws::{JwsAlgorithm, JwsContext, JwsVerifier, HS256};
use josekit::{JoseError, Value};
use serde_json::json;

use super::observe;

type Calls = Arc<Mutex<Vec<Value>>>;

fn record(calls: &Calls, value: Value) {
    calls.lock().expect("trace lock").push(value);
}

fn outcome(calls: &Calls, payload: Option<Vec<u8>>) -> Value {
    json!({"calls": *calls.lock().expect("trace lock"), "payload": payload})
}

fn rejected() -> JoseError {
    JoseError::InvalidSignature(anyhow::anyhow!("test backend rejected"))
}

#[derive(Clone, Debug)]
struct Verifier {
    calls: Calls,
    accepts: bool,
}

impl JwsVerifier for Verifier {
    fn algorithm(&self) -> &dyn JwsAlgorithm {
        &HS256
    }

    fn key_id(&self) -> Option<&str> {
        None
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), JoseError> {
        record(&self.calls, json!(["verify", message, signature]));
        self.accepts.then_some(()).ok_or_else(rejected)
    }

    fn box_clone(&self) -> Box<dyn JwsVerifier> {
        Box::new(self.clone())
    }
}

fn jws_cases(cases: &mut Vec<Value>) {
    let context = JwsContext::new();
    // Noncanonical JSON whitespace must be passed to the verifier in its original encoding.
    let header = URL_SAFE_NO_PAD.encode(br#"{ "alg" : "HS256" }"#);
    for (name, payload, signature, accepts) in [
        ("accepts", "AA", "AQ", true),
        ("rejects", "AA", "AQ", false),
        ("invalid payload after verification", "!", "AQ", true),
        ("invalid signature encoding", "AA", "AQ=", true),
    ] {
        let wire = format!("{header}.{payload}.{signature}");
        let calls = Calls::default();
        let verifier = Verifier {
            calls: calls.clone(),
            accepts,
        };
        let actual = context
            .deserialize_compact(&wire, &verifier)
            .ok()
            .map(|(payload, _)| payload);
        observe(
            cases,
            format!("Compact JWS callback {name}"),
            json!({"kind":"jwsFlow", "wire":wire, "accepts":accepts}),
            outcome(&calls, actual),
        );
    }
}

#[derive(Clone, Debug)]
struct Unwrapper {
    calls: Calls,
    key: Option<Vec<u8>>,
}

impl JweDecrypter for Unwrapper {
    fn algorithm(&self) -> &dyn JweAlgorithm {
        &A128KW
    }

    fn key_id(&self) -> Option<&str> {
        None
    }

    fn decrypt(
        &self,
        encrypted_key: Option<&[u8]>,
        _: &dyn JweContentEncryption,
        _: &JweHeader,
    ) -> Result<Cow<'_, [u8]>, JoseError> {
        record(&self.calls, json!(["unwrap", encrypted_key]));
        self.key.as_deref().map(Cow::Borrowed).ok_or_else(rejected)
    }

    fn box_clone(&self) -> Box<dyn JweDecrypter> {
        Box::new(self.clone())
    }
}

#[derive(Clone, Debug)]
struct Authenticator {
    calls: Calls,
    plaintext: Option<Vec<u8>>,
}

impl JweContentEncryption for Authenticator {
    fn name(&self) -> &str {
        "TRACE"
    }

    fn key_len(&self) -> usize {
        2
    }

    fn iv_len(&self) -> usize {
        1
    }

    fn encrypt(
        &self,
        _: &[u8],
        _: Option<&[u8]>,
        _: &[u8],
        _: &[u8],
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), JoseError> {
        unreachable!("decryption trace")
    }

    fn decrypt(
        &self,
        key: &[u8],
        iv: Option<&[u8]>,
        ciphertext: &[u8],
        aad: &[u8],
        tag: Option<&[u8]>,
    ) -> Result<Vec<u8>, JoseError> {
        record(
            &self.calls,
            json!(["authenticate", key, iv, ciphertext, aad, tag]),
        );
        self.plaintext.clone().ok_or_else(rejected)
    }

    fn box_clone(&self) -> Box<dyn JweContentEncryption> {
        Box::new(self.clone())
    }
}

#[derive(Clone, Debug)]
struct Compression {
    calls: Calls,
    output: Option<Vec<u8>>,
}

impl JweCompression for Compression {
    fn name(&self) -> &str {
        "TRACE"
    }

    fn compress(&self, _: &[u8]) -> io::Result<Vec<u8>> {
        unreachable!("decryption trace")
    }

    fn decompress(&self, data: &[u8]) -> io::Result<Vec<u8>> {
        record(&self.calls, json!(["decompress", data]));
        self.output
            .clone()
            .ok_or_else(|| io::Error::other("test decompression rejected"))
    }

    fn box_clone(&self) -> Box<dyn JweCompression> {
        Box::new(self.clone())
    }
}

fn jwe_cases(cases: &mut Vec<Value>) {
    let wrapped_key = "AQ";
    let key = Some(&[5u8, 6][..]);
    let plaintext = Some(&[7u8, 8][..]);
    let decompressed = Some(&[9u8][..]);
    for (name, key, plaintext, zip, decompressed, encoded_iv) in [
        ("accepts", key, plaintext, true, decompressed, "Ag"),
        ("no compression", key, plaintext, false, None, ""),
        ("unwrap rejects", None, plaintext, true, decompressed, "Ag"),
        (
            "wrong key length",
            Some(&[5][..]),
            plaintext,
            true,
            decompressed,
            "Ag",
        ),
        (
            "authentication rejects",
            key,
            None,
            true,
            decompressed,
            "Ag",
        ),
        ("decompression rejects", key, plaintext, true, None, "Ag"),
        (
            "invalid IV encoding",
            key,
            plaintext,
            true,
            decompressed,
            "Ag=",
        ),
    ] {
        let header = if zip {
            br#"{ "zip" : "TRACE", "enc" : "TRACE", "alg" : "A128KW" }"#.as_slice()
        } else {
            br#"{ "enc" : "TRACE", "alg" : "A128KW" }"#.as_slice()
        };
        let protected = URL_SAFE_NO_PAD.encode(header);
        let wire = format!("{protected}.{wrapped_key}.{encoded_iv}.Aw.BA");
        let calls = Calls::default();
        let mut context = JweContext::new();
        context.add_content_encryption(Box::new(Authenticator {
            calls: calls.clone(),
            plaintext: plaintext.map(<[u8]>::to_vec),
        }));
        context.add_compression(Box::new(Compression {
            calls: calls.clone(),
            output: decompressed.map(<[u8]>::to_vec),
        }));
        let unwrapper = Unwrapper {
            calls: calls.clone(),
            key: key.map(<[u8]>::to_vec),
        };
        let actual = context
            .deserialize_compact(&wire, &unwrapper)
            .ok()
            .map(|(data, _)| data);
        observe(
            cases,
            format!("Compact JWE callback {name}"),
            json!({
                "kind":"jweFlow", "wire":wire, "keySize":2, "key":key, "plaintext":plaintext,
                "zip":zip, "decompressed":decompressed,
            }),
            outcome(&calls, actual),
        );
    }
}

pub(super) fn collect(cases: &mut Vec<Value>) {
    jws_cases(cases);
    jwe_cases(cases);
}

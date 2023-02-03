pub mod der;
pub mod hash_algorithm;
pub mod oid;

use anyhow::bail;
use base64::DecodeError;
use base64::Engine as _;
use once_cell::sync::Lazy;
use openssl::bn::BigNumRef;
use openssl::rand;
use regex;

pub use crate::util::hash_algorithm::HashAlgorithm;

pub use HashAlgorithm::Sha1 as SHA_1;
pub use HashAlgorithm::Sha256 as SHA_256;
pub use HashAlgorithm::Sha384 as SHA_384;
pub use HashAlgorithm::Sha512 as SHA_512;

pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut vec = vec![0; len];
    rand::rand_bytes(&mut vec).unwrap();
    vec
}

pub(crate) fn ceiling(len: usize, div: usize) -> usize {
    (len + (div - 1)) / div
}

pub(crate) fn is_base64_standard(input: &str) -> bool {
    static RE_BASE64_STANDARD: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(
            r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?$",
        )
        .unwrap()
    });

    RE_BASE64_STANDARD.is_match(input)
}

pub(crate) fn is_base64_urlsafe_nopad(input: &str) -> bool {
    static RE_BASE64_URL_SAFE_NOPAD: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(
            r"^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-][AQgw]|[A-Za-z0-9_-]{2}[AEIMQUYcgkosw048])?$",
        )
        .unwrap()
    });

    RE_BASE64_URL_SAFE_NOPAD.is_match(input)
}

pub(crate) fn encode_base64_standard(input: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::STANDARD.encode(input)
}

pub(crate) fn decode_base64_standard(input: impl AsRef<[u8]>) -> Result<Vec<u8>, DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(input)
}

pub(crate) fn encode_base64_urlsafe_nopad(input: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(input)
}

pub(crate) fn encode_base64_urlsafe_nopad_buf(input: impl AsRef<[u8]>, output_buf: &mut String) {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode_string(input, output_buf);
}

pub(crate) fn decode_base64_urlsafe_no_pad(
    input: impl AsRef<[u8]>,
) -> Result<Vec<u8>, DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input)
}

pub(crate) fn parse_pem(input: &[u8]) -> anyhow::Result<(String, Vec<u8>)> {
    static RE_PEM: Lazy<regex::bytes::Regex> = Lazy::new(|| {
        regex::bytes::Regex::new(concat!(
            r"^",
            r"-----BEGIN ([A-Z0-9 -]+)-----[\t ]*(?:\r\n|[\r\n])",
            r"([\t\r\n a-zA-Z0-9+/=]+)",
            r"-----END ([A-Z0-9 -]+)-----[\t ]*(?:\r\n|[\r\n])?",
            r"$"
        ))
        .unwrap()
    });

    static RE_FILTER: Lazy<regex::bytes::Regex> =
        Lazy::new(|| regex::bytes::Regex::new("[\t\r\n ]").unwrap());

    let result = if let Some(caps) = RE_PEM.captures(input) {
        match (caps.get(1), caps.get(2), caps.get(3)) {
            (Some(ref m1), Some(ref m2), Some(ref m3)) if m1.as_bytes() == m3.as_bytes() => {
                let alg = String::from_utf8(m1.as_bytes().to_vec())?;
                let base64_data = RE_FILTER.replace_all(m2.as_bytes(), regex::bytes::NoExpand(b""));
                let data = decode_base64_standard(&base64_data)?;
                (alg, data)
            }
            _ => bail!("Mismatched the begging and ending label."),
        }
    } else {
        bail!("Invalid PEM format.");
    };

    Ok(result)
}

pub(crate) fn num_to_vec(num: &BigNumRef, len: usize) -> Vec<u8> {
    let vec = num.to_vec();
    if vec.len() < len {
        let mut tmp = Vec::with_capacity(len);
        for _ in 0..(len - vec.len()) {
            tmp.push(0);
        }
        tmp.extend_from_slice(&vec);
        tmp
    } else {
        vec
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_base64_standard() {
        assert_eq!(
            is_base64_standard("MA"),
            decode_base64_standard("MA").is_ok()
        );
        assert_eq!(
            is_base64_standard("MDEyMzQ1Njc4OQ"),
            decode_base64_standard("MDEyMzQ1Njc4OQ").is_ok()
        );
        assert_eq!(
            is_base64_standard("MDEyMzQ1Njc4OQ=="),
            decode_base64_standard("MDEyMzQ1Njc4OQ==").is_ok()
        );
        assert_eq!(
            is_base64_standard("MDEyMzQ1Njc4OQ="),
            decode_base64_standard("MDEyMzQ1Njc4OQ=").is_ok()
        );
        assert_eq!(
            is_base64_standard("MDEyMzQ1Njc4O"),
            decode_base64_standard("MDEyMzQ1Njc4O").is_ok()
        );
        assert_eq!(
            is_base64_standard("+/+/"),
            decode_base64_standard("+/+/").is_ok()
        );
        assert_eq!(
            is_base64_standard("A+/"),
            decode_base64_standard("A+/").is_ok()
        );
        assert_eq!(
            is_base64_standard("-_-_"),
            decode_base64_standard("-_-_").is_ok()
        );
        assert_eq!(
            is_base64_standard("AB<>"),
            decode_base64_standard("AB<>").is_ok()
        );
    }

    #[test]
    fn test_is_base64_url_safe_nopad() {
        assert_eq!(
            is_base64_urlsafe_nopad("MA"),
            decode_base64_urlsafe_no_pad("MA").is_ok()
        );
        assert_eq!(
            is_base64_urlsafe_nopad("MDEyMzQ1Njc4OQ"),
            decode_base64_urlsafe_no_pad("MDEyMzQ1Njc4OQ").is_ok()
        );
        assert_eq!(
            is_base64_urlsafe_nopad("MDEyMzQ1Njc4OQ=="),
            decode_base64_urlsafe_no_pad("MDEyMzQ1Njc4OQ==").is_ok()
        );
        assert_eq!(
            is_base64_urlsafe_nopad("MDEyMzQ1Njc4OQ="),
            decode_base64_urlsafe_no_pad("MDEyMzQ1Njc4OQ=").is_ok()
        );
        assert_eq!(
            is_base64_urlsafe_nopad("MDEyMzQ1Njc4O"),
            decode_base64_urlsafe_no_pad("MDEyMzQ1Njc4O").is_ok()
        );
        assert_eq!(
            is_base64_urlsafe_nopad("+/+/"),
            decode_base64_urlsafe_no_pad("+/+/").is_ok()
        );
        assert_eq!(
            is_base64_urlsafe_nopad("A+/"),
            decode_base64_urlsafe_no_pad("A+/").is_ok()
        );
        assert_eq!(
            is_base64_urlsafe_nopad("-_-_"),
            decode_base64_urlsafe_no_pad("-_-_").is_ok()
        );
        assert_eq!(
            is_base64_urlsafe_nopad("AB<>"),
            decode_base64_urlsafe_no_pad("AB<>").is_ok()
        );
    }
}

use anyhow::bail;
use once_cell::sync::Lazy;
use regex::bytes::{NoExpand, Regex};
use serde_json::{Map, Value};

pub fn json_eq(
    map: &Map<String, Value>,
    key: &str,
    value: &str,
    required: bool,
) -> anyhow::Result<()> {
    match map.get(key) {
        Some(Value::String(val)) if val == value => Ok(()),
        Some(Value::String(val)) => bail!("{} must be {}: {}", key, value, val),
        Some(val) => bail!("{} must be string: {}", key, val),
        None if !required => Ok(()),
        None => bail!("{} is missing.", key),
    }
}

pub fn json_in(
    map: &Map<String, Value>,
    key: &str,
    value: &str,
    required: bool,
) -> anyhow::Result<()> {
    match map.get(key) {
        Some(Value::Array(val)) => {
            let mut success = false;
            for item in val {
                if let Value::String(actual) = item {
                    if actual == value {
                        success = true;
                        break;
                    }
                }
            }
            if !success && required {
                bail!("{} must contain {}.", key, value);
            }
            Ok(())
        }
        Some(val) => bail!("{} must be array: {}", key, val),
        None if !required => Ok(()),
        None => bail!("{} is missing.", key),
    }
}

pub fn json_get<'a>(
    map: &'a Map<String, Value>,
    key: &'a str,
    required: bool,
) -> anyhow::Result<Option<&'a str>> {
    match map.get(key) {
        Some(Value::String(val)) => Ok(Some(val)),
        Some(val) => bail!("{} must be string: {}", key, val),
        None if !required => Ok(None),
        None => bail!("{} is missing.", key),
    }
}

pub fn parse_pem(input: &[u8]) -> anyhow::Result<(String, Vec<u8>)> {
    static RE_PEM: Lazy<Regex> = Lazy::new(|| {
        Regex::new(concat!(
            r"^",
            r"-----BEGIN ([A-Z0-9 -]+)-----[\t ]*(?:\r\n|[\r\n])",
            r"([\t\r\n a-zA-Z0-9+/=]+)",
            r"-----END ([A-Z0-9 -]+)-----[\t ]*(?:\r\n|[\r\n])?",
            r"$"
        ))
        .unwrap()
    });

    static RE_FILTER: Lazy<Regex> = Lazy::new(|| Regex::new("[\t\r\n ]").unwrap());

    let result = if let Some(caps) = RE_PEM.captures(input) {
        match (caps.get(1), caps.get(2), caps.get(3)) {
            (Some(ref m1), Some(ref m2), Some(ref m3)) if m1.as_bytes() == m3.as_bytes() => {
                let alg = String::from_utf8(m1.as_bytes().to_vec())?;
                let base64_data = RE_FILTER.replace_all(m2.as_bytes(), NoExpand(b""));
                let data = base64::decode_config(&base64_data, base64::STANDARD)?;
                (alg, data)
            }
            _ => bail!("Mismatched the begging and ending label."),
        }
    } else {
        bail!("Invalid PEM format.");
    };

    Ok(result)
}

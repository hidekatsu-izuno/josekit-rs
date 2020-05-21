use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value};

pub fn json_eq(map: &Map<String, Value>, key: &str, value: &str) -> Result<()>  {
    match map.get(key) {
        Some(val) if val == value => Ok(()),
        Some(val) => bail!("{} must be {}: {}", key, value, val),
        None => bail!("Key {} is missing.")
    }
}

pub fn json_base64_bytes(map: &Map<String, Value>, key: &str) -> Result<Vec<u8>>  {
    match map.get(key) {
        Some(Value::String(val)) => {
            let bytes = base64::decode_config(val, base64::URL_SAFE_NO_PAD)
                .map_err(|err| anyhow!(err))?;
            Ok(bytes)
        },
        Some(_) => bail!("Key {} is invalid.", key),
        None => bail!("Key {} is missing.", key)
    }
}

#![cfg(not(target_family = "wasm"))]

use std::env;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use anyhow::{bail, Result};
use josekit::jwe::{self, Dir, JweContext, JweHeader, JweHeaderSet};
use josekit::jwk::{Jwk, JwkSet};
use josekit::jws::{self, JwsContext, JwsHeader, JwsHeaderSet, HS256};
use josekit::jwt::{self, JwtContext, JwtPayload, JwtPayloadValidator};
use josekit::Value;
use serde_json::json;

#[path = "support/compact_flow.rs"]
mod compact_flow;

const SIGNING_KEY: &[u8] = &[0x42; 32];
const ENCRYPTION_KEY: &[u8] = &[0x51; 32];

fn observe(cases: &mut Vec<Value>, name: impl Into<String>, mut input: Value, actual: Value) {
    input["name"] = json!(name.into());
    input["actual"] = actual;
    cases.push(input);
}

#[test]
#[ignore = "requires the Lean 4 conformance checker built by verification/check.sh"]
fn public_api_matches_lean_spec() -> Result<()> {
    let checker = env::var_os("JOSEKIT_LEAN_CHECK").ok_or_else(|| {
        anyhow::anyhow!("Run verification/check.sh to build and run the Lean checker")
    })?;
    let mut cases = Vec::new();
    inspect_headers(&mut cases)?;
    compact_jws(&mut cases)?;
    compact_jwe(&mut cases)?;
    json_serializations(&mut cases)?;
    compact_flow::collect(&mut cases);
    external_vectors(&mut cases)?;
    validate_claims(&mut cases);
    let max_date_nanos = max_numeric_date_nanos();
    numeric_dates(&mut cases, max_date_nanos);
    base64url_cases(&mut cases)?;
    jwk_sets(&mut cases)?;

    let input = serde_json::to_vec(&json!({
        "maxDateNanos": max_date_nanos.to_string(),
        "cases": cases,
    }))?;
    let mut child = Command::new(checker).stdin(Stdio::piped()).spawn()?;
    let written = child
        .stdin
        .take()
        .expect("piped checker input")
        .write_all(&input);
    let status = child.wait()?;
    if !status.success() {
        bail!("Lean conformance checker exited with {status}");
    }
    written?;
    Ok(())
}

fn max_numeric_date_nanos() -> u128 {
    let mut lower = 0;
    let mut upper = Duration::MAX.as_nanos();
    while lower < upper {
        let nanos = lower + (upper - lower).div_ceil(2);
        let duration = Duration::new(
            (nanos / 1_000_000_000) as u64,
            (nanos % 1_000_000_000) as u32,
        );
        if SystemTime::UNIX_EPOCH.checked_add(duration).is_some() {
            lower = nanos;
        } else {
            upper = nanos - 1;
        }
    }
    lower
}

fn numeric_dates(cases: &mut Vec<Value>, max_date_nanos: u128) {
    let last_second = (max_date_nanos / 1_000_000_000) as u64;
    let mut values = vec![
        json!(0),
        json!(0.125),
        json!(-1),
        json!(1e100),
        json!(u64::MAX),
        json!(9_007_199_254_740_993u64),
        json!(last_second),
        json!("10"),
    ];
    if let Some(second) = last_second.checked_add(1) {
        values.push(json!(second));
    }
    let getters = [
        (
            "exp",
            JwtPayload::expires_at as fn(&JwtPayload) -> Option<SystemTime>,
        ),
        ("nbf", JwtPayload::not_before),
        ("iat", JwtPayload::issued_at),
    ];
    for (field, getter) in getters {
        for value in &values {
            let mut claims = josekit::Map::new();
            claims.insert(field.to_owned(), value.clone());
            let actual = JwtPayload::from_map(claims).ok().map(|payload| {
                getter(&payload)
                    .expect("a parsed NumericDate must have a SystemTime")
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .expect("a parsed NumericDate must be nonnegative")
                    .as_nanos()
                    .to_string()
            });
            observe(
                cases,
                format!("NumericDate {field}={value}"),
                json!({"kind":"numericDate","value":value}),
                json!(actual),
            );
        }
    }
}

fn malformed_shapes() -> [(&'static str, &'static str); 8] {
    [
        ("empty", ""),
        ("one part", "e30"),
        ("two parts", "e30."),
        ("four parts", "e30..."),
        ("six parts", "e30....."),
        ("padded header", "e30=.e30."),
        ("noncanonical base64url", "e31.e30."),
        ("non-object header", "W10.e30."),
    ]
}

fn inspect_headers(cases: &mut Vec<Value>) -> Result<()> {
    let compact_jws = sign(b"{}", json!({}), SIGNING_KEY)?;
    let compact_jwe = encrypt(b"{}", json!({"enc": "A256GCM"}))?;
    let header_only = replace_part(&compact_jws, 2, "not-a-signature!");
    for (name, wire) in [
        ("JWS", compact_jws.as_str()),
        ("JWE", compact_jwe.as_str()),
        ("inspect malformed signature", header_only.as_str()),
        ("JWS header without alg", "e30.."),
        ("JWE header without alg or enc", "e30...."),
        ("invalid UTF-8 header", "_w.."),
        ("JWS alg of wrong type", "eyJhbGciOjF9.."),
    ]
    .into_iter()
    .chain(malformed_shapes())
    {
        let actual = jwt::decode_header(wire).ok().map(|header| {
            let claims = match header.as_any().downcast_ref::<JwsHeader>() {
                Some(header) => header.claims_set(),
                None => header
                    .as_any()
                    .downcast_ref::<JweHeader>()
                    .expect("JWT header type")
                    .claims_set(),
            };
            json!(claims)
        });
        observe(
            cases,
            format!("inspect {name}"),
            json!({"kind": "inspect", "wire": wire}),
            json!(actual),
        );
    }
    Ok(())
}

fn sign(payload: &[u8], claims: Value, key: &[u8]) -> Result<String> {
    let header = JwsHeader::from_map(claims.as_object().expect("header object").clone())?;
    Ok(jws::serialize_compact(
        payload,
        &header,
        &HS256.signer_from_bytes(key)?,
    )?)
}

fn replace_part(wire: &str, index: usize, replacement: &str) -> String {
    let mut parts: Vec<_> = wire.split('.').collect();
    parts[index] = replacement;
    parts.join(".")
}

fn compact_jws(cases: &mut Vec<Value>) -> Result<()> {
    let payload = br#"{"sub":"reader"}"#;
    let normal = sign(payload, json!({"kid":"primary"}), SIGNING_KEY)?;
    let without_kid = sign(payload, json!({}), SIGNING_KEY)?;
    let other_key = sign(payload, json!({"kid":"primary"}), &[0x61; 32])?;
    let empty = sign(b"", json!({}), SIGNING_KEY)?;
    let binary = sign(&[0, 255, 128], json!({}), SIGNING_KEY)?;
    let raw = sign(payload, json!({"crit":["b64"],"b64":false}), SIGNING_KEY)?;
    let critical_b64 = sign(payload, json!({"crit":["b64"],"b64":true}), SIGNING_KEY)?;
    let extension = sign(
        payload,
        json!({"crit":["example"],"example":42}),
        SIGNING_KEY,
    )?;
    let bad_claims = [
        ("array payload", sign(b"[]", json!({}), SIGNING_KEY)?),
        (
            "invalid date type",
            sign(br#"{"exp":"today"}"#, json!({}), SIGNING_KEY)?,
        ),
        (
            "negative date",
            sign(br#"{"iat":-1}"#, json!({}), SIGNING_KEY)?,
        ),
        (
            "out of range NumericDates",
            sign(
                br#"{"exp":1e100,"nbf":1e100,"iat":1e100}"#,
                json!({}),
                SIGNING_KEY,
            )?,
        ),
        (
            "invalid audience",
            sign(br#"{"aud":["reader",1]}"#, json!({}), SIGNING_KEY)?,
        ),
    ];
    let changed_payload = replace_part(&normal, 1, "e30");
    let changed_signature = replace_part(&normal, 2, "AA");
    let padded_signature = format!("{normal}=");
    let malformed_payload = replace_part(&normal, 1, "!");
    let wrong_alg = replace_part(&normal, 0, "eyJhbGciOiJIUzM4NCJ9");
    let unsecured = jwt::encode_unsecured(&JwtPayload::new(), &JwsHeader::new())?;
    let unsecured_bad_signature = replace_part(&unsecured, 2, "AA");

    let mut record = |name: &str,
                      wire: &str,
                      reference: &str,
                      alg: &str,
                      kid: Option<&str>,
                      critical: &[&str],
                      is_jwt: bool|
     -> Result<()> {
        let mut context = JwsContext::new();
        let mut jwt_context = JwtContext::new();
        for name in critical {
            context.add_acceptable_critical(name);
            jwt_context.add_acceptable_critical(name);
        }
        let mut hmac_verifier = HS256.verifier_from_bytes(SIGNING_KEY)?;
        if let Some(kid) = kid {
            hmac_verifier.set_key_id(kid);
        }
        let unsecured_verifier = jwt::None.verifier();
        let verifier: &dyn jws::JwsVerifier = match alg {
            "none" => &unsecured_verifier,
            _ => &hmac_verifier,
        };
        let actual = if is_jwt {
            json!(jwt_context
                .decode_with_verifier(wire, verifier)
                .ok()
                .map(|(payload, _)| payload.claims_set().clone()))
        } else {
            json!(context
                .deserialize_compact(wire, verifier)
                .ok()
                .map(|(payload, _)| payload))
        };
        observe(
            cases,
            format!("{} {name}", if is_jwt { "JWT" } else { "JWS" }),
            json!({"kind":"jws", "wire":wire, "reference":reference, "jwt":is_jwt,
                "policy":{"alg":alg, "kid":kid, "critical":critical}}),
            actual,
        );
        Ok(())
    };

    for (name, wire, expected_key, critical) in [
        ("default verification", normal.as_str(), None, &[][..]),
        ("matching kid", normal.as_str(), Some("primary"), &[][..]),
        ("wrong kid", normal.as_str(), Some("secondary"), &[][..]),
        (
            "missing kid",
            without_kid.as_str(),
            Some("primary"),
            &[][..],
        ),
        ("wrong key", other_key.as_str(), None, &[][..]),
        ("wrong alg", wrong_alg.as_str(), None, &[][..]),
        ("changed payload", changed_payload.as_str(), None, &[][..]),
        (
            "changed signature",
            changed_signature.as_str(),
            None,
            &[][..],
        ),
        ("padded signature", padded_signature.as_str(), None, &[][..]),
        (
            "invalid base64url payload",
            malformed_payload.as_str(),
            None,
            &[][..],
        ),
        ("empty payload", empty.as_str(), None, &[][..]),
        ("binary payload", binary.as_str(), None, &[][..]),
        ("unsupported critical", extension.as_str(), None, &[][..]),
        (
            "accepted critical",
            extension.as_str(),
            None,
            &["example"][..],
        ),
        ("unencoded payload disabled", raw.as_str(), None, &[][..]),
        (
            "unencoded payload enabled",
            raw.as_str(),
            None,
            &["b64"][..],
        ),
    ] {
        let reference = if name == "wrong key" { &normal } else { wire };
        let reference = match name {
            "changed payload" | "changed signature" | "wrong alg" => &normal,
            _ => reference,
        };
        record(
            name,
            wire,
            reference,
            "HS256",
            expected_key,
            critical,
            false,
        )?;
    }
    for (name, wire) in malformed_shapes() {
        record(name, wire, &normal, "HS256", None, &[], false)?;
    }

    record("signed", &normal, &normal, "HS256", None, &[], true)?;
    record(
        "plain header with b64 registered",
        &normal,
        &normal,
        "HS256",
        None,
        &["b64"],
        true,
    )?;
    record("b64 false", &raw, &raw, "HS256", None, &["b64"], true)?;
    record(
        "b64 true",
        &critical_b64,
        &critical_b64,
        "HS256",
        None,
        &["b64"],
        true,
    )?;
    record("unsecured", &unsecured, &unsecured, "none", None, &[], true)?;
    record(
        "unsecured with signature",
        &unsecured_bad_signature,
        &unsecured,
        "none",
        None,
        &[],
        true,
    )?;
    record(
        "none with HS256 verifier",
        &unsecured,
        &unsecured,
        "HS256",
        None,
        &[],
        true,
    )?;
    for (name, wire) in bad_claims {
        record(name, &wire, &wire, "HS256", None, &[], true)?;
    }
    Ok(())
}

fn encrypt(payload: &[u8], claims: Value) -> Result<String> {
    let header = JweHeader::from_map(claims.as_object().expect("header object").clone())?;
    Ok(jwe::serialize_compact(
        payload,
        &header,
        &Dir.encrypter_from_bytes(ENCRYPTION_KEY)?,
    )?)
}

fn compact_jwe(cases: &mut Vec<Value>) -> Result<()> {
    let payload = br#"{"iss":"issuer"}"#;
    let normal = encrypt(payload, json!({"enc":"A256GCM","kid":"primary"}))?;
    let no_kid = encrypt(payload, json!({"enc":"A256GCM"}))?;
    let cbc = encrypt(b"", json!({"enc":"A128CBC-HS256","zip":"DEF"}))?;
    let critical = encrypt(
        payload,
        json!({"enc":"A256GCM","crit":["example"],"example":1}),
    )?;
    let non_json = encrypt(b"[]", json!({"enc":"A256GCM"}))?;
    let mut record = |name: &str,
                      wire: &str,
                      reference: &str,
                      plaintext: Option<&[u8]>,
                      kid: Option<&str>,
                      options: &[&str],
                      is_jwt: bool,
                      wrong_key: bool|
     -> Result<()> {
        let mut context = JweContext::new();
        let mut jwt_context = JwtContext::new();
        for name in options {
            context.add_acceptable_critical(name);
            jwt_context.add_acceptable_critical(name);
        }
        let key = if wrong_key {
            &[0x62; 32][..]
        } else {
            ENCRYPTION_KEY
        };
        let mut decrypter = Dir.decrypter_from_bytes(key)?;
        if let Some(kid) = kid {
            decrypter.set_key_id(kid);
        }
        let actual = if is_jwt {
            json!(jwt_context
                .decode_with_decrypter(wire, &decrypter)
                .ok()
                .map(|(payload, _)| payload.claims_set().clone()))
        } else {
            json!(context
                .deserialize_compact(wire, &decrypter)
                .ok()
                .map(|(payload, _)| payload))
        };
        observe(
            cases,
            format!("{} {name}", if is_jwt { "JWT/JWE" } else { "JWE" }),
            json!({"kind":"jwe", "wire":wire, "reference":reference, "plaintext":plaintext,
                "jwt":is_jwt, "policy":{"alg":"dir", "kid":kid, "critical":options}}),
            actual,
        );
        Ok(())
    };

    record(
        "valid",
        &normal,
        &normal,
        Some(payload),
        None,
        &[],
        false,
        false,
    )?;
    record(
        "matching kid",
        &normal,
        &normal,
        Some(payload),
        Some("primary"),
        &[],
        false,
        false,
    )?;
    record(
        "wrong kid",
        &normal,
        &normal,
        Some(payload),
        Some("secondary"),
        &[],
        false,
        false,
    )?;
    record(
        "missing kid",
        &no_kid,
        &no_kid,
        Some(payload),
        Some("primary"),
        &[],
        false,
        false,
    )?;
    record("wrong key", &normal, &normal, None, None, &[], false, true)?;
    record(
        "CBC-HMAC with DEF",
        &cbc,
        &cbc,
        Some(b""),
        None,
        &[],
        false,
        false,
    )?;
    record(
        "unsupported critical",
        &critical,
        &critical,
        Some(payload),
        None,
        &[],
        false,
        false,
    )?;
    record(
        "accepted critical",
        &critical,
        &critical,
        Some(payload),
        None,
        &["example"],
        false,
        false,
    )?;
    for (name, index, replacement) in [
        (
            "changed protected header",
            0,
            "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0",
        ),
        (
            "unknown content encryption",
            0,
            "eyJhbGciOiJkaXIiLCJlbmMiOiJ1bmtub3duIn0",
        ),
        ("invalid encrypted key", 1, "AA"),
        ("missing IV", 2, ""),
        ("changed ciphertext", 3, "AA"),
        ("missing tag", 4, ""),
        ("padded tag", 4, "AA=="),
    ] {
        record(
            name,
            &replace_part(&normal, index, replacement),
            &normal,
            Some(payload),
            None,
            &[],
            false,
            false,
        )?;
    }
    for (name, wire) in malformed_shapes() {
        record(name, wire, &normal, Some(payload), None, &[], false, false)?;
    }
    record(
        "encrypted claims",
        &normal,
        &normal,
        Some(payload),
        None,
        &[],
        true,
        false,
    )?;
    record(
        "encrypted non-object",
        &non_json,
        &non_json,
        Some(b"[]"),
        None,
        &[],
        true,
        false,
    )?;
    let out_of_range = br#"{"exp":1e100}"#;
    let wire = encrypt(out_of_range, json!({"enc":"A256GCM"}))?;
    record(
        "encrypted out of range NumericDate",
        &wire,
        &wire,
        Some(out_of_range),
        None,
        &[],
        true,
        false,
    )?;
    Ok(())
}

fn json_serializations(cases: &mut Vec<Value>) -> Result<()> {
    let payload = b"JSON serialization";
    let signer = HS256.signer_from_bytes(SIGNING_KEY)?;
    let verifier = HS256.verifier_from_bytes(SIGNING_KEY)?;
    let mut header = JwsHeaderSet::new();
    header.set_key_id("primary", true);
    header.set_token_type("example", false);
    let flattened: Value =
        serde_json::from_str(&jws::serialize_flattened_json(payload, &header, &signer)?)?;
    let general: Value = serde_json::from_str(&jws::serialize_general_json(
        payload,
        &[(&header, &signer), (&header, &signer)],
    )?)?;
    let mut overlap = flattened.clone();
    overlap["header"]["kid"] = json!("primary");
    let mut unprotected_crit = flattened.clone();
    unprotected_crit["header"]["crit"] = json!(["example"]);
    let mut changed_payload = flattened.clone();
    changed_payload["payload"] = json!("e30");
    for (name, wire, reference) in [
        ("flattened", &flattened, &flattened),
        ("general", &general, &general),
        ("duplicate kid", &overlap, &flattened),
        ("unprotected crit", &unprotected_crit, &flattened),
        ("changed payload", &changed_payload, &flattened),
    ] {
        let actual = jws::deserialize_json(serde_json::to_vec(wire)?, &verifier)
            .ok()
            .map(|(payload, _)| payload);
        observe(
            cases,
            format!("JWS JSON {name}"),
            json!({"kind":"jsonJws", "wire":wire,
            "reference":reference, "policy":{"alg":"HS256","kid":null,"critical":[]}}),
            json!(actual),
        );
    }

    let encrypter = Dir.encrypter_from_bytes(ENCRYPTION_KEY)?;
    let decrypter = Dir.decrypter_from_bytes(ENCRYPTION_KEY)?;
    let mut shared = JweHeaderSet::new();
    shared.set_content_encryption("A256GCM", true);
    shared.set_token_type("example", false);
    let mut recipient = JweHeader::new();
    recipient.set_key_id("primary");
    let aad = Some(&b"external data"[..]);
    let flattened: Value = serde_json::from_str(&jwe::serialize_flattened_json(
        payload,
        Some(&shared),
        Some(&recipient),
        aad,
        &encrypter,
    )?)?;
    let general: Value = serde_json::from_str(&jwe::serialize_general_json(
        payload,
        Some(&shared),
        &[(Some(&recipient), &encrypter)],
        aad,
    )?)?;
    let mut overlap = flattened.clone();
    overlap["header"]["typ"] = json!("example");
    let mut unprotected_crit = flattened.clone();
    unprotected_crit["unprotected"]["crit"] = json!(["example"]);
    let mut changed_aad = flattened.clone();
    changed_aad["aad"] = json!("e30");
    let mut missing_iv = flattened.clone();
    missing_iv
        .as_object_mut()
        .expect("JWE JSON object")
        .remove("iv");
    let mut record = |name: &str,
                      wire: &Value,
                      reference: &Value,
                      plaintext: &[u8]|
     -> Result<()> {
        let actual = jwe::deserialize_json(&serde_json::to_string(wire)?, &decrypter)
            .ok()
            .map(|(payload, _)| payload);
        observe(
            cases,
            format!("JWE JSON {name}"),
            json!({"kind":"jsonJwe","wire":wire,
            "reference":reference,"plaintext":plaintext,"policy":{"alg":"dir","kid":null,"critical":[]}}),
            json!(actual),
        );
        Ok(())
    };
    for (name, wire, reference) in [
        ("flattened", &flattened, &flattened),
        ("general", &general, &general),
        ("duplicate typ", &overlap, &flattened),
        ("unprotected crit", &unprotected_crit, &flattened),
        ("changed AAD", &changed_aad, &flattened),
        ("missing IV", &missing_iv, &flattened),
    ] {
        record(name, wire, reference, payload)?;
    }
    for (description, plaintext, aad) in [
        ("empty ciphertext", &b""[..], None),
        ("empty external AAD", &payload[..], Some(&b""[..])),
    ] {
        let flattened: Value = serde_json::from_str(&jwe::serialize_flattened_json(
            plaintext,
            Some(&shared),
            Some(&recipient),
            aad,
            &encrypter,
        )?)?;
        let general: Value = serde_json::from_str(&jwe::serialize_general_json(
            plaintext,
            Some(&shared),
            &[(Some(&recipient), &encrypter)],
            aad,
        )?)?;
        record(
            &format!("flattened {description}"),
            &flattened,
            &flattened,
            plaintext,
        )?;
        record(
            &format!("general {description}"),
            &general,
            &general,
            plaintext,
        )?;
    }
    shared.set_algorithm("dir", true);
    let general: Value = serde_json::from_str(&jwe::serialize_general_json(
        payload,
        Some(&shared),
        &[(None, &encrypter)],
        None,
    )?)?;
    record(
        "general with an empty recipient",
        &general,
        &general,
        payload,
    )?;
    Ok(())
}

fn external_vectors(cases: &mut Vec<Value>) -> Result<()> {
    let wire = include_str!("../data/jwt/HS256.jwt");
    let key = Jwk::from_bytes(include_bytes!("../data/jwk/oct_512bit_private.jwk"))?;
    let verifier = HS256.verifier_from_jwk(&key)?;
    let actual = jwt::decode_with_verifier(wire, &verifier)
        .ok()
        .map(|(payload, _)| payload.claims_set().clone());
    observe(
        cases,
        "external HS256 JWT",
        json!({"kind":"jws", "wire":wire,
        "reference":wire, "jwt":true, "policy":{"alg":"HS256","kid":null,"critical":[]}}),
        json!(actual),
    );

    let wire = include_str!("../data/jwt/dir_A256GCM_DEF.jwt");
    let key = Jwk::from_bytes(include_bytes!("../data/jwk/oct_256bit_private.jwk"))?;
    let decrypter = Dir.decrypter_from_jwk(&key)?;
    let plaintext: &[u8] = br#"{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}"#;
    let actual = jwt::decode_with_decrypter(wire, &decrypter)
        .ok()
        .map(|(payload, _)| payload.claims_set().clone());
    observe(
        cases,
        "external dir A256GCM DEF JWT",
        json!({"kind":"jwe", "wire":wire,
        "reference":wire, "jwt":true, "plaintext":plaintext,
        "policy":{"alg":"dir","kid":null,"critical":[]}}),
        json!(actual),
    );
    Ok(())
}

fn validate_claims(cases: &mut Vec<Value>) {
    let mut validator = JwtPayloadValidator::new();
    let epoch = SystemTime::UNIX_EPOCH;
    validator.set_base_time(epoch + Duration::from_secs(10));
    validator.set_min_issued_time(epoch + Duration::from_secs(3));
    validator.set_max_issued_time(epoch + Duration::from_secs(7));
    validator.set_audience("reader");
    validator.set_issuer("issuer");
    validator.set_claim("custom", json!({"scope":["read"]}));

    let mut record = |name: String, claims: Value| {
        let accepted = claims.as_object().is_some_and(|object| {
            JwtPayload::from_map(object.clone()).is_ok_and(|p| validator.validate(&p).is_ok())
        });
        observe(
            cases,
            name,
            json!({"kind":"claims", "claims":claims, "policy":{
                "base":10_000_000_000u64, "minIssued":3_000_000_000u64, "maxIssued":7_000_000_000u64,
                "audience":"reader", "required":{"iss":"issuer","custom":{"scope":["read"]}}
            }}),
            json!(accepted),
        );
    };

    let baseline = json!({"iss":"issuer","custom":{"scope":["read"]}});
    for nbf in [None, Some(9.5), Some(10.0), Some(10.5)] {
        for exp in [None, Some(9.5), Some(10.0), Some(10.5)] {
            for iat in [None, Some(2.5), Some(3.0), Some(5.0), Some(7.0), Some(7.5)] {
                let mut claims = baseline.clone();
                for (name, value) in [("nbf", nbf), ("exp", exp), ("iat", iat)] {
                    if let Some(value) = value {
                        claims[name] = json!(value);
                    }
                }
                record(
                    format!("claims nbf={nbf:?} exp={exp:?} iat={iat:?}"),
                    claims,
                );
            }
        }
    }
    for (field, value) in [
        ("aud", json!("reader")),
        ("aud", json!(["other", "reader"])),
        ("aud", json!("other")),
        ("aud", json!([])),
        ("aud", json!([1])),
        ("iss", json!("other")),
        ("iss", json!(1)),
        ("exp", json!(-1)),
        ("exp", json!(1e100)),
        ("custom", json!({"scope":["write"]})),
        ("custom", Value::Null),
    ] {
        let mut claims = baseline.clone();
        claims[field] = value.clone();
        record(format!("claims {field}={value}"), claims);
    }
    record("missing required claim".into(), json!({"iss":"issuer"}));
    record("non-object claims".into(), json!([]));
}

fn base64url_cases(cases: &mut Vec<Value>) -> Result<()> {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for prefix in ["A", "AB", "ABC"] {
        for last in alphabet.chars().chain(['=', '+', '/', ' ', 'é']) {
            let encoded = format!("{prefix}{last}");
            let value = json!({"kty":"oct","k":encoded});
            let actual = Jwk::from_bytes(serde_json::to_vec(&value)?)
                .ok()
                .and_then(|key| key.key_value());
            observe(
                cases,
                format!("Base64url {encoded:?}"),
                json!({"kind":"base64url","encoded":encoded}),
                json!(actual),
            );
        }
    }
    Ok(())
}

fn jwk_sets(cases: &mut Vec<Value>) -> Result<()> {
    let a = json!({"kty":"oct","kid":"shared","k":"AA"});
    let b = json!({"kty":"oct","kid":"shared","k":"AQ"});
    let c = json!({"kty":"oct","kid":"other","k":"Ag"});
    let no_kid = json!({"kty":"oct","k":"Aw"});
    let empty_kid = json!({"kty":"oct","kid":"","k":"BA"});
    for (name, value) in [
        ("valid", a.clone()),
        ("no kid", no_kid.clone()),
        ("missing kty", json!({})),
        ("invalid kid", json!({"kty":"oct","kid":7})),
        ("noncanonical k", json!({"kty":"oct","k":"AB"})),
        ("invalid key_ops", json!({"kty":"oct","key_ops":["sign",0]})),
        ("extension", json!({"kty":"example","data":42})),
    ] {
        let actual = Jwk::from_bytes(serde_json::to_vec(&value)?).is_ok();
        observe(
            cases,
            format!("JWK {name}"),
            json!({"kind":"jwk","value":value}),
            json!(actual),
        );
    }
    let initial = json!({"keys":[a, c, b, a, no_kid, empty_kid],"extra":"metadata"});
    for (name, value) in [
        ("empty", json!({"keys":[]})),
        ("populated", initial.clone()),
        ("missing keys", json!({})),
        ("invalid keys", json!({"keys":1})),
        ("invalid member", json!({"keys":[a,[]]})),
        ("invalid JWK", json!({"keys":[{}]})),
    ] {
        let actual = JwkSet::from_bytes(serde_json::to_vec(&value)?).is_ok();
        observe(
            cases,
            format!("JWK Set {name}"),
            json!({"kind":"keySet","value":value}),
            json!(actual),
        );
    }

    record_key_set_trace(
        cases,
        "JWK Set ordered mutation trace",
        &initial,
        &[
            ("inspect", &a),
            ("remove", &a),
            ("push", &b),
            ("remove", &c),
            ("remove", &no_kid),
            ("remove", &a),
            ("remove", &a),
            ("push", &a),
            ("remove", &empty_kid),
            ("push", &empty_kid),
        ],
    )?;
    let choices = [("push", &a), ("push", &b), ("remove", &a), ("remove", &b)];
    let empty = json!({"keys":[]});
    for first in choices {
        for second in choices {
            for third in choices {
                for fourth in choices {
                    let steps = [first, second, third, fourth];
                    let label = steps
                        .map(|(action, key)| format!("{action} {}", key["k"]))
                        .join(", ");
                    record_key_set_trace(cases, format!("JWK Set trace {label}"), &empty, &steps)?;
                }
            }
        }
    }
    Ok(())
}

fn record_key_set_trace(
    cases: &mut Vec<Value>,
    name: impl Into<String>,
    initial: &Value,
    steps: &[(&str, &Value)],
) -> Result<()> {
    let mut keys = JwkSet::from_bytes(serde_json::to_vec(initial)?)?;
    let queries = ["shared", "other", "", "missing"];
    let mut operations = Vec::new();
    let mut snapshots = Vec::new();
    for &(action, value) in steps {
        let key = Jwk::from_bytes(serde_json::to_vec(value)?)?;
        match action {
            "push" => keys.push_key(key),
            "remove" => keys.remove_key(&key),
            _ => {}
        }
        operations.push(json!({"action":action,"key":value}));
        let displayed: Value = serde_json::from_str(&keys.to_string())?;
        let lookups: Vec<_> = queries.iter().map(|id| keys.get(id)).collect();
        snapshots.push(json!({"keys":keys.keys(), "mapKeys":keys.as_ref()["keys"],
            "displayKeys":displayed["keys"], "lookups":lookups}));
    }
    observe(
        cases,
        name,
        json!({"kind":"keySetTrace",
        "initial":initial, "queries":queries, "operations":operations}),
        json!(snapshots),
    );
    Ok(())
}

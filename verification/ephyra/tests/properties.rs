use std::time::{Duration, SystemTime};

use ephyra::gens;
use josekit::jwe::{self, Dir, JweContext, JweHeader, JweHeaderSet, A128KW};
use josekit::jwk::{Jwk, JwkSet};
use josekit::jws::{self, JwsContext, JwsHeaderSet, HS256};
use josekit::jwt::{JwtContext, JwtPayload, JwtPayloadValidator};
use josekit::{JoseError, Map, Value};
use serde_json::json;

const KEY: &[u8; 32] = &[17; 32];

fn gcm_headers() -> (JweHeaderSet, JweHeader) {
    let mut shared = JweHeaderSet::new();
    shared.set_content_encryption("A256GCM", true);
    let mut recipient = JweHeader::new();
    recipient.set_key_id("audit-recipient");
    (shared, recipient)
}

fn gcm_json(
    general: bool,
    payload: &[u8],
    aad: Option<&[u8]>,
) -> Result<(Vec<u8>, Value), JoseError> {
    let (shared, recipient) = gcm_headers();
    let encrypter = Dir.encrypter_from_bytes(KEY)?;
    let decrypter = Dir.decrypter_from_bytes(KEY)?;
    let token = if general {
        jwe::serialize_general_json(
            payload,
            Some(&shared),
            &[(Some(&recipient), &encrypter)],
            aad,
        )
    } else {
        jwe::serialize_flattened_json(payload, Some(&shared), Some(&recipient), aad, &encrypter)
    }?;
    let parsed: Value = serde_json::from_str(&token).expect("serializer must produce JSON");
    let (plaintext, _) = jwe::deserialize_json(&token, &decrypter)?;
    Ok((plaintext, parsed))
}

#[ephyra::test(gen = (gens::bool(), gens::vec(gens::int(..)).len(0..=32)), tests = 6000)]
fn jwe_json_round_trips_empty_or_nonempty_plaintext(case: (bool, Vec<u8>)) {
    let (general, payload) = case;
    let (decoded, wire) = gcm_json(general, &payload, None).expect("valid GCM JSON round trip");
    assert_eq!(wire["ciphertext"].as_str() == Some(""), payload.is_empty());
    assert_eq!(decoded, payload);
}

#[ephyra::test(gen = (gens::bool(), gens::vec(gens::int(..)).len(1..=32), gens::vec(gens::int(..)).len(0..=16)), tests = 6000)]
fn jwe_json_round_trips_empty_or_nonempty_external_aad(case: (bool, Vec<u8>, Vec<u8>)) {
    let (general, payload, aad) = case;
    let (decoded, wire) =
        gcm_json(general, &payload, Some(&aad)).expect("valid GCM JSON round trip with AAD");
    assert_eq!(wire.get("aad").is_some(), !aad.is_empty());
    assert_eq!(decoded, payload);
}

#[ephyra::test(gen = gens::vec(gens::int(..)).len(1..=32), tests = 6000)]
fn jwe_general_allows_alg_in_shared_protected_header(payload: Vec<u8>) {
    let mut shared = JweHeaderSet::new();
    shared.set_content_encryption("A256GCM", true);
    shared.set_algorithm("A128KW", true);
    let encrypter = A128KW.encrypter_from_bytes(&KEY[..16]).unwrap();
    let decrypter = A128KW.decrypter_from_bytes(&KEY[..16]).unwrap();
    let token = jwe::serialize_general_json(&payload, Some(&shared), &[(None, &encrypter)], None)
        .expect("a recipient with an encrypted key can use only shared JOSE headers");
    let (decoded, _) = jwe::deserialize_json(&token, &decrypter).unwrap();
    assert_eq!(decoded, payload);
}

#[ephyra::test(gen = (gens::bool(), gens::string_len(gens::char(), 0..=64)), tests = 6000)]
fn jws_json_unencoded_text_round_trips(case: (bool, String)) {
    let (general, payload) = case;
    let mut context = JwsContext::new();
    context.add_acceptable_critical("b64");
    let mut headers = JwsHeaderSet::new();
    headers.set_critical(&vec!["b64"]);
    headers.set_base64url_encode_payload(false);
    let signer = HS256.signer_from_bytes(KEY).unwrap();
    let verifier = HS256.verifier_from_bytes(KEY).unwrap();
    let token = if general {
        jws::serialize_general_json(payload.as_bytes(), &[(&headers, &signer)])
    } else {
        jws::serialize_flattened_json(payload.as_bytes(), &headers, &signer)
    }
    .unwrap();
    let (decoded, _) = context.deserialize_json(token, &verifier).unwrap();
    assert_eq!(decoded, payload.as_bytes());
}

fn epoch(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

#[ephyra::test(gen = (
    gens::int(0u64..=30),
    gens::option(gens::int(0u64..=30)),
    gens::option(gens::int(0u64..=30)),
    gens::option(gens::int(0u64..=30)),
), tests = 6000)]
fn jwt_integral_time_checks_match_model(input: (u64, Option<u64>, Option<u64>, Option<u64>)) {
    let (now, exp, nbf, iat) = input;
    let mut validator = JwtPayloadValidator::new();
    validator.set_base_time(epoch(now));
    validator.set_min_issued_time(epoch(5));
    validator.set_max_issued_time(epoch(20));
    let mut payload = JwtPayload::new();
    for (claim, value) in [("exp", exp), ("nbf", nbf), ("iat", iat)] {
        if let Some(value) = value {
            payload.set_claim(claim, Some(json!(value))).unwrap();
        }
    }
    let accept = exp.is_none_or(|t| now < t)
        && nbf.is_none_or(|t| t <= now)
        && iat.is_none_or(|t| (5..=20).contains(&t));
    assert_eq!(validator.validate(&payload).is_ok(), accept);
}

const IDS: [&str; 3] = ["", "a", "b"];

#[ephyra::test(gen = gens::vec((gens::bool(), gens::option(gens::int(0usize..=2)), gens::int(0u8..=6))).len(0..=40), tests = 6000)]
fn jwk_set_index_matches_ordered_list(ops: Vec<(bool, Option<usize>, u8)>) {
    let mut set = JwkSet::new();
    let mut expected = Vec::new();
    for (push, kid, val) in ops {
        let mut key = Jwk::new("oct");
        key.set_key_value([val]);
        if let Some(kid) = kid {
            key.set_key_id(IDS[kid]);
        }
        if push {
            set.push_key(key.clone());
            expected.push(key);
        } else {
            set.remove_key(&key);
            if let Some(index) = expected.iter().position(|other| other == &key) {
                expected.remove(index);
            }
        }
        assert!(set.keys().into_iter().eq(expected.iter()));
        for kid in IDS.into_iter().chain(["missing"]) {
            assert!(set
                .get(kid)
                .into_iter()
                .eq(expected.iter().filter(|key| key.key_id() == Some(kid))));
        }
    }
}

#[ephyra::test(tests = 16)]
fn fresh_context_equals_its_clone(jwt: bool) {
    if jwt {
        let context = JwtContext::new();
        assert_eq!(context, context.clone());
    } else {
        let context = JweContext::new();
        assert_eq!(context, context.clone());
    }
}

fn assert_integer_dates_round_trip(seconds: u64) {
    let mut payload = JwtPayload::new();
    let Some(input) = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds)) else {
        for claim in ["nbf", "iat"] {
            assert!(payload.set_claim(claim, Some(json!(seconds))).is_err());
        }
        return;
    };
    payload.set_not_before(&input);
    payload.set_issued_at(&input);
    assert_eq!(payload.not_before(), Some(input));
    assert_eq!(payload.issued_at(), Some(input));

    let claims: Map<String, Value> = serde_json::from_str(&payload.to_string()).unwrap();
    let decoded = JwtPayload::from_map(claims).unwrap();
    assert_eq!(decoded.not_before(), Some(input));
    assert_eq!(decoded.issued_at(), Some(input));
}

#[ephyra::test(gen = gens::int((1u64 << 53)..=((1u64 << 53) + 2048)), tests = 6000)]
fn jwt_dates_near_the_float_precision_boundary_survive_json_round_trip(seconds: u64) {
    assert_integer_dates_round_trip(seconds);
}

#[ephyra::test(gen = gens::int((1u64 << 43)..=((i64::MAX as u64) / 1024)), tests = 6000)]
fn jwt_large_exact_times_survive_json_round_trip(units: u64) {
    assert_integer_dates_round_trip(units * 1024);
}

#[ephyra::test(gen = gens::int(0u64..=(1u64 << 53)), tests = 6000)]
fn jwt_whole_seconds_survive_json_round_trip(seconds: u64) {
    assert_integer_dates_round_trip(seconds);
}

#[ephyra::test(gen = gens::int(0u64..=u64::from(u32::MAX)), tests = 6000)]
fn jwt_ordinary_times_survive_json_round_trip(seconds: u64) {
    assert_integer_dates_round_trip(seconds);
}

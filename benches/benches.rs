use std::{hint::black_box, time::SystemTime};

use criterion::{
    criterion_group, criterion_main, measurement::WallTime, BenchmarkGroup, BenchmarkId, Criterion,
};
use josekit::{jwe, jws, jwt, util::random_bytes, Value};

const RSA_PRIVATE_KEY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/data/pem/RSA_2048bit_private.pem"
);
const RSA_PUBLIC_KEY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/data/pem/RSA_2048bit_public.pem"
);

const EC_P256K_PRIVATE_KEY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/data/pem/EC_secp256k1_private.pem"
);
const EC_P256K_PUBLIC_KEY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/data/pem/EC_secp256k1_public.pem"
);

const EC_P256_PRIVATE_KEY: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/pem/EC_P-256_private.pem");
const EC_P256_PUBLIC_KEY: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/pem/EC_P-256_public.pem");

const EC_P384_PRIVATE_KEY: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/pem/EC_P-384_private.pem");
const EC_P384_PUBLIC_KEY: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/pem/EC_P-384_public.pem");

const EC_P521_PRIVATE_KEY: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/pem/EC_P-521_private.pem");
const EC_P521_PUBLIC_KEY: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/pem/EC_P-521_public.pem");

const ED25519_PRIVATE_KEY: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/pem/ED25519_private.pem");
const ED25519_PUBLIC_KEY: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/data/pem/ED25519_public.pem");

fn encode_benchmarks(group: &mut BenchmarkGroup<WallTime>, signer: &dyn jws::JwsSigner) {
    let mut header = jws::JwsHeader::new();
    header.set_token_type("JWT");
    header.set_algorithm(signer.algorithm().name());

    let mut payload = jwt::JwtPayload::new();
    payload.set_subject("1234567890");
    payload
        .set_claim("name", Some(Value::String("John Doe".to_string())))
        .unwrap();
    payload.set_claim("admin", Some(Value::Bool(true))).unwrap();
    payload.set_issued_at(&SystemTime::now());

    let id = BenchmarkId::new("encode_with_signer", signer.algorithm().name());
    group.bench_with_input(id, &(header, payload), |b, input| {
        b.iter(|| {
            jwt::encode_with_signer(black_box(&input.1), black_box(&input.0), black_box(signer))
        });
    });
}

fn decode_benchmarks(
    group: &mut BenchmarkGroup<WallTime>,
    verifier: &dyn jws::JwsVerifier,
    token: impl AsRef<[u8]>,
) {
    let id = BenchmarkId::new("decode_with_verifier", verifier.algorithm().name());
    group.bench_with_input(id, &token, |b, input| {
        b.iter(|| jwt::decode_with_verifier(black_box(input), black_box(verifier)).unwrap());
    });
}

fn encrypt_benchmarks(
    group: &mut BenchmarkGroup<WallTime>,
    encrypter: &dyn jwe::JweEncrypter,
    content_encryption: &str,
) {
    let mut header = jwe::JweHeader::new();
    header.set_token_type("JWT");
    header.set_algorithm(encrypter.algorithm().name());
    header.set_content_encryption(content_encryption);

    let mut payload = jwt::JwtPayload::new();
    payload.set_subject("1234567890");
    payload
        .set_claim("name", Some(Value::String("John Doe".to_string())))
        .unwrap();
    payload.set_claim("admin", Some(Value::Bool(true))).unwrap();
    payload.set_issued_at(&SystemTime::now());

    let id = BenchmarkId::new(
        "encode_with_encrypter",
        format! {"{}/{}", encrypter.algorithm().name(), content_encryption},
    );

    group.bench_with_input(id, &(header, payload), |b, input| {
        b.iter(|| {
            jwt::encode_with_encrypter(
                black_box(&input.1),
                black_box(&input.0),
                black_box(encrypter),
            )
        });
    });
}

fn decrypt_benchmarks(
    group: &mut BenchmarkGroup<WallTime>,
    decrypter: &dyn jwe::JweDecrypter,
    token: impl AsRef<[u8]>,
    content_encryption: &str,
) {
    let id = BenchmarkId::new(
        "decode_with_decrypter",
        format! {"{}/{}", decrypter.algorithm().name(), content_encryption},
    );

    group.bench_with_input(id, &token, |b, input| {
        b.iter(|| jwt::decode_with_decrypter(black_box(input), black_box(decrypter)).unwrap());
    });
}

fn create_signed_token(signer: &dyn jws::JwsSigner) -> String {
    let mut header = jws::JwsHeader::new();
    header.set_token_type("JWT");
    header.set_algorithm(signer.algorithm().name());

    let mut payload = jwt::JwtPayload::new();
    payload.set_subject("1234567890");
    payload
        .set_claim("name", Some(Value::String("John Doe".to_string())))
        .unwrap();
    payload.set_claim("admin", Some(Value::Bool(true))).unwrap();
    payload.set_issued_at(&SystemTime::now());
    jwt::encode_with_signer(&payload, &header, signer).unwrap()
}

fn create_encrypted_token(encrypter: &dyn jwe::JweEncrypter, content_encryption: &str) -> String {
    let mut header = jwe::JweHeader::new();
    header.set_token_type("JWT");
    header.set_algorithm(encrypter.algorithm().name());
    header.set_content_encryption(content_encryption);

    let mut payload = jwt::JwtPayload::new();
    payload.set_subject("1234567890");
    payload
        .set_claim("name", Some(Value::String("John Doe".to_string())))
        .unwrap();
    payload.set_claim("admin", Some(Value::Bool(true))).unwrap();
    payload.set_issued_at(&SystemTime::now());
    jwt::encode_with_encrypter(&payload, &header, encrypter).unwrap()
}

fn bench(c: &mut Criterion) {
    // utils
    let mut group = c.benchmark_group("Utils");
    {
        group.bench_function("random_bytes", |b| b.iter(|| random_bytes(black_box(32))));
    }
    group.finish();

    // JWS encode
    let mut group = c.benchmark_group("JWS encode");
    {
        encode_benchmarks(&mut group, &jwt::None.signer());
        for alg in [(jws::HS256, 32), (jws::HS384, 48), (jws::HS512, 64)] {
            let key = random_bytes(alg.1);
            let signer = alg.0.signer_from_bytes(key).unwrap();
            encode_benchmarks(&mut group, &signer);
        }
    }
    {
        let private_key = std::fs::read(RSA_PRIVATE_KEY).unwrap();

        for alg in [jws::RS256, jws::RS384, jws::RS512] {
            let signer = alg.signer_from_pem(&private_key).unwrap();
            encode_benchmarks(&mut group, &signer);
        }
    }
    {
        for alg in [
            (jws::ES256K, EC_P256K_PRIVATE_KEY),
            (jws::ES256, EC_P256_PRIVATE_KEY),
            (jws::ES384, EC_P384_PRIVATE_KEY),
            (jws::ES512, EC_P521_PRIVATE_KEY),
        ] {
            let private_key = std::fs::read(alg.1).unwrap();
            let signer = alg.0.signer_from_pem(&private_key).unwrap();
            encode_benchmarks(&mut group, &signer);
        }
    }
    {
        let private_key = std::fs::read(ED25519_PRIVATE_KEY).unwrap();
        let signer = jws::EdDSA.signer_from_pem(&private_key).unwrap();
        encode_benchmarks(&mut group, &signer);
    }
    group.finish();

    // JWS decode
    let mut group = c.benchmark_group("JWS decode");
    {
        let (signer, verifier) = (jwt::None.signer(), jwt::None.verifier());
        let token = create_signed_token(&signer);
        decode_benchmarks(&mut group, &verifier, token);
    }
    {
        for alg in [(jws::HS256, 32), (jws::HS384, 48), (jws::HS512, 64)] {
            let key = random_bytes(alg.1);
            let signer = alg.0.signer_from_bytes(&key).unwrap();
            let verifier = alg.0.verifier_from_bytes(&key).unwrap();
            let token = create_signed_token(&signer);
            decode_benchmarks(&mut group, &verifier, token);
        }
    }
    {
        let private_key = std::fs::read(RSA_PRIVATE_KEY).unwrap();
        let public_key = std::fs::read(RSA_PUBLIC_KEY).unwrap();

        for alg in [jws::RS256, jws::RS384, jws::RS512] {
            let signer = alg.signer_from_pem(&private_key).unwrap();
            let verifier = alg.verifier_from_pem(&public_key).unwrap();
            let token = create_signed_token(&signer);
            decode_benchmarks(&mut group, &verifier, token);
        }
    }
    {
        for alg in [
            (jws::ES256K, EC_P256K_PRIVATE_KEY, EC_P256K_PUBLIC_KEY),
            (jws::ES256, EC_P256_PRIVATE_KEY, EC_P256_PUBLIC_KEY),
            (jws::ES384, EC_P384_PRIVATE_KEY, EC_P384_PUBLIC_KEY),
            (jws::ES512, EC_P521_PRIVATE_KEY, EC_P521_PUBLIC_KEY),
        ] {
            let private_key = std::fs::read(alg.1).unwrap();
            let public_key = std::fs::read(alg.2).unwrap();
            let signer = alg.0.signer_from_pem(&private_key).unwrap();
            let verifier = alg.0.verifier_from_pem(&public_key).unwrap();
            let token = create_signed_token(&signer);
            decode_benchmarks(&mut group, &verifier, token);
        }
    }
    {
        let private_key = std::fs::read(ED25519_PRIVATE_KEY).unwrap();
        let public_key = std::fs::read(ED25519_PUBLIC_KEY).unwrap();
        let signer = jws::EdDSA.signer_from_pem(&private_key).unwrap();
        let verifier = jws::EdDSA.verifier_from_pem(&public_key).unwrap();
        let token = create_signed_token(&signer);
        decode_benchmarks(&mut group, &verifier, token);
    }
    group.finish();

    // JWE encode
    let mut group = c.benchmark_group("JWE encode");
    {
        // direct
        for alg in [
            jwe::enc::A128CBC_HS256,
            jwe::enc::A192CBC_HS384,
            jwe::enc::A256CBC_HS512,
        ] {
            let key = random_bytes(alg.key_len());
            let encrypter = jwe::Dir.encrypter_from_bytes(key).unwrap();
            encrypt_benchmarks(&mut group, &encrypter, alg.name());
        }
        for alg in [jwe::enc::A128GCM, jwe::enc::A192GCM, jwe::enc::A256GCM] {
            let key = random_bytes(alg.key_len());
            let encrypter = jwe::Dir.encrypter_from_bytes(key).unwrap();
            encrypt_benchmarks(&mut group, &encrypter, alg.name());
        }

        // AESKW
        for alg in [
            (jwe::A128KW, jwe::enc::A128CBC_HS256, 16),
            (jwe::A192KW, jwe::enc::A192CBC_HS384, 24),
            (jwe::A256KW, jwe::enc::A256CBC_HS512, 32),
        ] {
            let kw_alg = alg.0;
            let ce_alg = alg.1;
            let key_len = alg.2;

            let key = random_bytes(key_len);
            let encrypter = kw_alg.encrypter_from_bytes(&key).unwrap();
            encrypt_benchmarks(&mut group, &encrypter, ce_alg.name());
        }
        for alg in [
            (jwe::A128GCMKW, jwe::enc::A128GCM, 16),
            (jwe::A192GCMKW, jwe::enc::A192GCM, 24),
            (jwe::A256GCMKW, jwe::enc::A256GCM, 32),
        ] {
            let kw_alg = alg.0;
            let ce_alg = alg.1;
            let key_len = alg.2;

            let key = random_bytes(key_len);
            let encrypter = kw_alg.encrypter_from_bytes(&key).unwrap();
            encrypt_benchmarks(&mut group, &encrypter, ce_alg.name());
        }
    }
    group.finish();

    // JWE decode
    let mut group = c.benchmark_group("JWE decode");
    {
        // direct
        for alg in [
            jwe::enc::A128CBC_HS256,
            jwe::enc::A192CBC_HS384,
            jwe::enc::A256CBC_HS512,
        ] {
            let key = random_bytes(alg.key_len());
            let encrypter = jwe::Dir.encrypter_from_bytes(&key).unwrap();
            let decrypter = jwe::Dir.decrypter_from_bytes(&key).unwrap();
            let token = create_encrypted_token(&encrypter, alg.name());
            decrypt_benchmarks(&mut group, &decrypter, token, alg.name());
        }
        for alg in [jwe::enc::A128GCM, jwe::enc::A192GCM, jwe::enc::A256GCM] {
            let key = random_bytes(alg.key_len());
            let encrypter = jwe::Dir.encrypter_from_bytes(&key).unwrap();
            let decrypter = jwe::Dir.decrypter_from_bytes(&key).unwrap();
            let token = create_encrypted_token(&encrypter, alg.name());
            decrypt_benchmarks(&mut group, &decrypter, token, alg.name());
        }

        // AESKW
        for alg in [
            (jwe::A128KW, jwe::enc::A128CBC_HS256, 16),
            (jwe::A192KW, jwe::enc::A192CBC_HS384, 24),
            (jwe::A256KW, jwe::enc::A256CBC_HS512, 32),
        ] {
            let kw_alg = alg.0;
            let ce_alg = alg.1;
            let key_len = alg.2;

            let key = random_bytes(key_len);
            let encrypter = kw_alg.encrypter_from_bytes(&key).unwrap();
            let decrypter = kw_alg.decrypter_from_bytes(&key).unwrap();
            let token = create_encrypted_token(&encrypter, ce_alg.name());
            decrypt_benchmarks(&mut group, &decrypter, token, ce_alg.name());
        }
        for alg in [
            (jwe::A128GCMKW, jwe::enc::A128GCM, 16),
            (jwe::A192GCMKW, jwe::enc::A192GCM, 24),
            (jwe::A256GCMKW, jwe::enc::A256GCM, 32),
        ] {
            let kw_alg = alg.0;
            let ce_alg = alg.1;
            let key_len = alg.2;

            let key = random_bytes(key_len);
            let encrypter = kw_alg.encrypter_from_bytes(&key).unwrap();
            let decrypter = kw_alg.decrypter_from_bytes(&key).unwrap();
            let token = create_encrypted_token(&encrypter, ce_alg.name());
            decrypt_benchmarks(&mut group, &decrypter, token, ce_alg.name());
        }
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);

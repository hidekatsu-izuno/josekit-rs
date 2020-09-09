# josekit

JOSE (Javascript Object Signing and Encryption: JWT, JWS, JWE, JWA, JWK) library for Rust.

## Install

```toml
[dependencies]
josekit = "0.4.0"
```

This library depends on OpenSSL DLL. Read more about [Crate openssl](https://docs.rs/openssl/). 

## Build

```sh
sudo apt install build-essential pkg-config libssl-dev
cd josekit-rs
cargo build --release
```

## Supported signing algorithms

<table>
<thead>
    <tr>
        <th>Name</th>
        <th>Description</th>
        <th>Key Type</th>
    </tr>
</thead>
<tbody>
    <tr>
        <td>HS256</td>
        <td>HMAC using SHA-256</td>
        <td>oct (size: 256 bits or more)</td>
    </tr>
    <tr>
        <td>HS384</td>
        <td>HMAC using SHA-384</td>
        <td>oct (size: 384 bits or more)</td>
    </tr>
    <tr>
        <td>HS512</td>
        <td>HMAC using SHA-512</td>
        <td>oct (size: 512 bits or more)</td>
    </tr>
    <tr>
        <td>RS256</td>
        <td>RSASSA-PKCS1-v1_5 using SHA-256</td>
        <td rowspan="6">RSA (size: 1024 bits or more)</td>
    </tr>
    <tr>
        <td>RS384</td>
        <td>RSASSA-PKCS1-v1_5 using SHA-384</td>
    </tr>
    <tr>
        <td>RS512</td>
        <td>RSASSA-PKCS1-v1_5 using SHA-512</td>
    </tr>
    <tr>
        <td>PS256</td>
        <td>RSASSA-PSS using SHA-256 and MGF1 with SHA-256</td>
    </tr>
    <tr>
        <td>PS384</td>
        <td>RSASSA-PSS using SHA-384 and MGF1 with SHA-384</td>
    </tr>
    <tr>
        <td>PS512</td>
        <td>RSASSA-PSS using SHA-512 and MGF1 with SHA-512</td>
    </tr>
    <tr>
        <td>ES256</td>
        <td>ECDSA using P-256 and SHA-256</td>
        <td>EC (curve: P-256)</td>
    </tr>
    <tr>
        <td>ES384</td>
        <td>ECDSA using P-384 and SHA-384</td>
        <td>EC (curve: P-384)</td>
    </tr>
    <tr>
        <td>ES512</td>
        <td>ECDSA using P-521 and SHA-512</td>
        <td>EC (curve: P-521)</td>
    </tr>
    <tr>
        <td>ES256K</td>
        <td>ECDSA using secp256k1 curve and SHA-256</td>
        <td>EC (curve: secp256k1)</td>
    </tr>
    <tr>
        <td>EdDSA</td>
        <td>EdDSA signature algorithms</td>
        <td>OKP (curve: Ed25519 or Ed448)</td>
    </tr>
    <tr>
        <td>none</td>
        <td>No digital signature or MAC performed</td>
        <td>-</td>
    </tr>
</tbody>
</table>

## Supported key formats for asymmetric signing

### Private Key

<table>
<thead>
<tr>
    <th rowspan="2">Algorithm</th>
    <th rowspan="2">JWK</th>
    <th colspan="2">PEM</th>
    <th colspan="2">DER</th>
</tr>
<tr>
    <th>PKCS#8</th>
    <th>Traditional</th>
    <th>PKCS#8</th>
    <th>Raw</th>
</tr>
</thead>
<tbody>
<tr>
    <td>RSASSA</td>
    <td>OK</td>
    <td>OK</td>
    <td>OK</td>
    <td>OK</td>
    <td>OK</td>
</tr>
<tr>
    <td>RSASSA-PSS</td>
    <td>OK</td>
    <td>OK</td>
    <td>OK</td>
    <td>OK</td>
    <td>-</td>
</tr>
<tr>
    <td>ECDSA</td>
    <td>OK</td>
    <td>OK</td>
    <td>OK</td>
    <td>OK</td>
    <td>OK</td>
</tr>
<tr>
    <td>EdDSA</td>
    <td>OK</td>
    <td>OK</td>
    <td>OK</td>
    <td>OK</td>
    <td>-</td>
</tr>
</tbody>
</table>

### Public Key

<table>
<thead>
<tr>
    <th rowspan="2">Algorithm</th>
    <th rowspan="2">JWK</th>
    <th colspan="2">PEM</th>
    <th colspan="2">DER</th>
</tr>
<tr>
    <th>SPKI</th>
    <th>Traditional</th>
    <th>SPKI</th>
    <th>Raw</th>
</tr>
</thead>
<tbody>
<tr>
    <td>RSASSA</td>
    <td>OK</td>
    <td>OK</td>
    <td>OK</td>
    <td>OK</td>
    <td>OK</td>
</tr>
<tr>
    <td>RSASSA-PSS</td>
    <td>OK</td>
    <td>OK</td>
    <td>OK</td>
    <td>OK</td>
    <td>OK</td>
</tr>
<tr>
    <td>ECDSA</td>
    <td>OK</td>
    <td>OK</td>
    <td>-</td>
    <td>OK</td>
    <td>-</td>
</tr>
<tr>
    <td>EdDSA</td>
    <td>OK</td>
    <td>OK</td>
    <td>-</td>
    <td>OK</td>
    <td>-</td>
</tr>
</tbody>
</table>

## Supported encryption algorithms

<table>
<thead>
    <tr>
        <th>Name</th>
        <th>Description</th>
        <th>Key Type</th>
    </tr>
</thead>
<tbody>
    <tr>
        <td>Dir</td>
        <td>Direct use of a shared symmetric key as the CEK</td>
        <td>oct (size: enc type depended)</td>
    </tr>
    <tr>
        <td>ECDH-ES</td>
        <td>Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF</td>
        <td rowspan="4">EC (curve: P-256, P-384, P-521 or secp256k1)<br />
            OKP (curve: X25519 or X448)</td>
    </tr>
    <tr>
        <td>ECDH-ES+A128KW</td>
        <td>ECDH-ES using Concat KDF and CEK wrapped with "A128KW"</td>
    </tr>
    <tr>
        <td>ECDH-ES+A192KW</td>
        <td>ECDH-ES using Concat KDF and CEK wrapped with "A192KW"</td>
    </tr>
    <tr>
        <td>ECDH-ES+A256KW</td>
        <td>ECDH-ES using Concat KDF and CEK wrapped with "A256KW"</td>
    </tr>
    <tr>
        <td>A128KW</td>
        <td>AES Key Wrap with default initial value using 128-bit key</td>
        <td>oct (size: 128 bits)</td>
    </tr>
    <tr>
        <td>A192KW</td>
        <td>AES Key Wrap with default initial value using 192-bit key</td>
        <td>oct (size: 192 bits)</td>
    </tr>
    <tr>
        <td>A256KW</td>
        <td>AES Key Wrap with default initial value using 256-bit key</td>
        <td>oct (size: 256 bits)</td>
    </tr>
    <tr>
        <td>A128GCMKW</td>
        <td>Key wrapping with AES GCM using 128-bit key</td>
        <td>oct (size: 128 bits)</td>
    </tr>
    <tr>
        <td>A192GCMKW</td>
        <td>Key wrapping with AES GCM using 192-bit key</td>
        <td>oct (size: 192 bits)</td>
    </tr>
    <tr>
        <td>A256GCMKW</td>
        <td>Key wrapping with AES GCM using 256-bit key</td>
        <td>oct (size: 256 bits)</td>
    </tr>
    <tr>
        <td>PBES2-HS256+A128KW</td>
        <td>PBES2 with HMAC SHA-256 and "A128KW" wrapping</td>
        <td>oct (size: 128 bits)</td>
    </tr>
    <tr>
        <td>PBES2-HS384+A192KW</td>
        <td>PBES2 with HMAC SHA-384 and "A192KW" wrapping</td>
        <td>oct (size: 192 bits)</td>
    </tr>
    <tr>
        <td>PBES2-HS512+A256KW</td>
        <td>PBES2 with HMAC SHA-512 and "A256KW" wrapping</td>
        <td>oct (size: 256 bits)</td>
    </tr>
    <tr>
        <td>RSA1_5</td>
        <td>RSAES-PKCS1-v1_5</td>
        <td rowspan="2">RSA (size: 1024 bits or more)</td>
    </tr>
    <tr>
        <td>RSA-OAEP</td>
        <td>RSAES OAEP using default parameters</td>
    </tr>
<!--
    <tr>
        <td>RSA-OAEP-256</td>
        <td>RSAES OAEP using SHA-256 and MGF1 with SHA-256</td>
    </tr>
    <tr>
        <td>RSA-OAEP-384</td>
        <td>RSAES OAEP using SHA-384 and MGF1 with SHA-384</td>
    </tr>
    <tr>
        <td>RSA-OAEP-512</td>
        <td>RSAES OAEP using SHA-512 and MGF1 with SHA-512</td>
    </tr>
-->
</tbody>
</table>

RSA-OAEP-256, RSA-OAEP-384 and RSA-OAEP-512 are not supported yet.

## Usage

### Signing a JWT by HMAC

HMAC is used to verify the integrity of a message by common secret key.
Three types of HMAC algorithms are available: HS256, HS384, and HS512.
You can use any text as the key.

```rust
use josekit::jws::{ JwsHeader, HS256 };
use josekit::jwt::{ self, JwtPayload };

let mut header = JwsHeader::new();
header.set_token_type("JWT");

let mut payload = JwtPayload::new();
payload.set_subject("subject");

let common_secret_key = b"secret";

// Signing JWT
let signer = HS256.signer_from_bytes(private_key)?;
let jwt = jwt::encode_with_signer(&payload, &header, &signer)?;

// Verifing JWT
let verifier = HS256.signer_from_bytes(private_key)?
let (payload, header) = jwt::decode_with_verifier(&jwt, &verifier)?;
```

### Signing a JWT by RSASSA

RSASSA is used to verify the integrity of a message by two keys: public and private.
Three types of RSASSA algorithms are available: RS256, RS384, and RS512.

You can generate the keys by executing openssl command.

```sh
# Generate a new private key. Keygen bits must be 2048 or more.
openssl openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out RSA_private.pem

# Generate a public key from the private key.
openssl pkey -in RSA_private.pem -pubout -outform PEM -out RSA_public.pem
```

```rust
use josekit::jws::{ JwsHeader, RS256 };
use josekit::jwt::{ self, JwtPayload };

let mut header = JwsHeader::new();
header.set_token_type("JWT");

let mut payload = JwtPayload::new();
payload.set_subject("subject");

// Signing JWT
let private_key = load_from_file("rsa_private.pem")?;
let signer = RS256.signer_from_pem(&private_key)?;
let jwt = jwt::encode_with_signer(&payload, &header, &signer)?;

// Verifing JWT
let public_key = load_from_file("rsa_public.pem")?;
let verifier = RS256.verifier_from_pem(&public_key)?;
let (payload, header) = jwt::decode_with_verifier(&jwt, &verifier)?;
```

### Signing a JWT by RSASSA-PSS

RSASSA-PSS is used to verify the integrity of a message by two keys: public and private.

The raw key format of RSASSA-PSS is the same as RSASSA. So you should use a PKCS#8 wrapped key. It contains some optional attributes.

Three types of RSASSA-PSS algorithms are available: PS256, PS384, and PS512.
You can generate the keys by executing openssl command.

```sh
# Generate a new private key

# for PS256
openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_pss_keygen_md:sha256 -pkeyopt rsa_pss_keygen_mgf1_md:sha256 -pkeyopt rsa_pss_keygen_saltlen:32 -out RSA-PSS_private.pem

# for PS384
openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_pss_keygen_md:sha384 -pkeyopt rsa_pss_keygen_mgf1_md:sha384 -pkeyopt rsa_pss_keygen_saltlen:48 -out RSA-PSS_private.pem

# for PS512
openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_pss_keygen_md:sha512 -pkeyopt rsa_pss_keygen_mgf1_md:sha512 -pkeyopt rsa_pss_keygen_saltlen:64 -out RSA-PSS_private.pem

# Generate a public key from the private key.
openssl pkey -in RSA-PSS_private.pem -pubout -outform PEM -out RSA-PSS_public.pem
```

```rust
use josekit::jws::{ JwsHeader, PS256 };
use josekit::jwt::{ self, JwtPayload };

let mut header = JwsHeader::new();
header.set_token_type("JWT");

let mut payload = JwtPayload::new();
payload.set_subject("subject");

// Signing JWT
let private_key = load_from_file("rsapss_private.pem")?;
let signer = PS256.signer_from_pem(&private_key)?;
let jwt = jwt::encode_with_signer(&payload, &header, &signer)?;

// Verifing JWT
let public_key = load_from_file("rsapss_public.pem")?;
let verifier = PS256.verifier_from_pem(&public_key)?;
let (payload, header) = jwt::decode_with_verifier(&jwt, &verifier)?;
```

### Signing a JWT by ECDSA

ECDSA is used to verify the integrity of a message by two keys: public and private.
Four types of ECDSA algorithms are available: ES256, ES384, ES512 and ES256K.

You can generate the keys by executing openssl command.

```sh
# Generate a new private key

# for ES256
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -outform PEM -out ECDSA_private.pem

# for ES384
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -outform PEM -out ECDSA_private.pem

# for ES512
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -outform PEM -out ECDSA_private.pem

# for ES256K
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp256k1 -outform PEM -out ECDSA_private.pem

# Generate a public key from the private key.
openssl pkey -in ECDSA_private.pem -pubout -outform PEM -out ECDSA_public.pem
```

```rust
use josekit::jws::{ JwsHeader, ES256 };
use josekit::jwt::{ self, JwtPayload };

let mut header = JwsHeader::new();
header.set_token_type("JWT");

let mut payload = JwtPayload::new();
payload.set_subject("subject");

// Signing JWT
let private_key = load_from_file("ECDSA_private.pem")?;
let signer = ES256.signer_from_pem(&private_key)?;
let jwt = jwt::encode_with_signer(&payload, &header, &signer)?;

// Verifing JWT
let public_key = load_from_file("ECDSA_public.pem")?;
let verifier = ES256.verifier_from_pem(&public_key)?;
let (payload, header) = jwt::decode_with_verifier(&jwt, &verifier)?;
```

### Signing a JWT by EdDSA

EdDSA is used to verify the integrity of a message by two keys: public and private.
Types of EdDSA algorithms is only "EdDSA".
But it has two curve types: Ed25519, Ed448.

You can generate the keys by executing openssl command.

```sh
# Generate a new private key

# for Ed25519
openssl genpkey -algorithm ED25519 -out Ed25519_private.pem

# for Ed448
openssl genpkey -algorithm ED448 -out Ed448_private.pem

# Generate a public key from the private key.
openssl pkey -in Ed25519_private.pem -pubout -outform PEM -out Ed25519_public.pem
```

```rust
use josekit::jws::{ JwsHeader, EdDSA };
use josekit::jwt::{ self, JwtPayload };

let mut header = JwsHeader::new();
header.set_token_type("JWT");

let mut payload = JwtPayload::new();
payload.set_subject("subject");

// Signing JWT
let private_key = load_from_file("Ed25519_private.pem")?;
let signer = EdDSA.signer_from_pem(&private_key)?;
let jwt = jwt::encode_with_signer(&payload, &header, &signer)?;

// Verifing JWT
let public_key = load_from_file("Ed25519_public.pem")?;
let verifier = EdDSA.verifier_from_pem(&public_key)?;
let (payload, header) = jwt::decode_with_verifier(&jwt, &verifier)?;
```

### Encrypted JWT

Not support yet.

### Unsecured JWT

```rust
use josekit::jws::JwsHeader;
use josekit::jwt::{self, JwtPayload};

let mut header = JwsHeader::new();
header.set_token_type("JWT");

let mut payload = JwtPayload::new();
payload.set_subject("subject");

let jwt = jwt::encode_unsecured(&payload, &header)?;
let (payload, header) = jwt::decode_unsecured(&jwt)?;
```

### Validate payload

```rust
use josekit::jwt::{self, JwtPayloadValidator };

...
let (payload, _) = jwt::decode_with_verifier(&jwt, &verifier)?;

let mut validator = JwtPayloadValidator::new();
// value based validation
validator.set_issuer("http://example.com");
validator.set_audience("user1");
validator.set_jwt_id("550e8400-e29b-41d4-a716-446655440000");

// time based validation: not_before <= base_time < expires_at
validator.set_base_time(SystemTime::now() + Duration::from_secs(30));

// issued time based validation: min_issued_time <= issued_time <= max_issued_time
validator.set_min_issued_time(SystemTime::now() - Duration::from_secs(48 * 60));
validator.set_max_issued_time(SystemTime::now() + Duration::from_secs(24 * 60));

validator.validate(&payload)?;
```

## ToDo

- Test JWE

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

## References

- [RFC7515: JSON Web Signature (JWS)](https://tools.ietf.org/html/rfc7515)
- [RFC7516: JSON Web Encryption (JWE)](https://tools.ietf.org/html/rfc7516)
- [RFC7517: JSON Web Key (JWK)](https://tools.ietf.org/html/rfc7517)
- [RFC7518: JSON Web Algorithms (JWA)](https://tools.ietf.org/html/rfc7518)
- [RFC7519: JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [RFC7797: JSON Web Signature (JWS) Unencoded Payload Option](https://tools.ietf.org/html/rfc7797)
- [RFC8017: PKCS #1: RSA Cryptography Specifications Version 2.2](https://tools.ietf.org/html/rfc8017)
- [RFC5208: PKCS #8: Private-Key Information Syntax Specification Version 1.2](https://tools.ietf.org/html/rfc5208)
- [RFC5280: Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile](https://tools.ietf.org/html/rfc5280)
- [RFC5480: Elliptic Curve Cryptography Subject Public Key Information](https://tools.ietf.org/html/rfc5480)
- [RFC5915: Elliptic Curve Private Key Structure](https://tools.ietf.org/html/rfc5915)
- [RFC6979: Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)](https://tools.ietf.org/html/rfc6979)
- [RFC8410: Algorithm Identifiers for Ed25519, Ed448, X25519, and X448 for Use in the Internet X.509 Public Key Infrastructure](https://tools.ietf.org/html/rfc8410)
- [RFC8037: CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JSON Object Signing and Encryption (JOSE)](https://tools.ietf.org/html/rfc8037)
- [RFC7468: Textual Encodings of PKIX, PKCS, and CMS Structures](https://tools.ietf.org/html/rfc7468)

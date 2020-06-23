# JWT-RS

JWT (JSON Web Token) library for rust (based on OpenSSL).

## Install

```toml
[dependencies]
jwt_rs = { git = "https://github.com/hidekatsu-izuno/jwt-rs" }
```

This library depends on OpenSSL DLL. Read more about it [Crate openssl](https://docs.rs/openssl/0.10.29/openssl/). 

## Build

```sh
sudo apt install build-essential pkg-config libssl-dev
cd jwt-rs
cargo build --release
```

## Supported signature algorithms

|Name  |Description                                   |Curve         |
|------|----------------------------------------------|--------------|
|HS256 |HMAC using SHA-256                            |              |
|HS384 |HMAC using SHA-384                            |              |
|HS512 |HMAC using SHA-512                            |              |
|RS256 |RSASSA-PKCS1-v1_5 using SHA-256               |              |
|RS384 |RSASSA-PKCS1-v1_5 using SHA-384               |              |
|RS512 |RSASSA-PKCS1-v1_5 using SHA-512               |              |
|PS256 |RSASSA-PSS using SHA-256 and MGF1 with SHA-256|              |
|PS384 |RSASSA-PSS using SHA-384 and MGF1 with SHA-384|              |
|PS512 |RSASSA-PSS using SHA-512 and MGF1 with SHA-512|              |
|ES256 |ECDSA using P-256 and SHA-256                 |              |
|ES384 |ECDSA using P-384 and SHA-384                 |              |
|ES512 |ECDSA using P-521 and SHA-512                 |              |
|ES256K|ECDSA using secp256k1 curve and SHA-256       |              |
|EdDSA |EdDSA signature algorithms                    |Ed25519, Ed448|
|None  |No digital signature or MAC performed         |              |

## Supported key formats for RSA/RSA-PSS/ECDSA/EdDSA sigining

<table>
<tr>
    <th rowspan="2">Algorithm<th>
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
<tr>
    <td>RSA</td>
    <td>OK</td>
    <td>OK</td>
    <td>OK</td>
    <td>OK</td>
    <td>OK</td>
</tr>
<tr>
    <td>RSA-PSS</td>
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
</table>

## Usage

### Signing a JWT by HMAC

HMAC is used to verify the integrity of a message by common secret key.
Three types of HMAC algorithms are available: HS256, HS384, and HS512.
You can use any text as the key.

```rust
use jwt_rs::{ Jwt, HS256 };

let mut jwt = Jwt::new();
jwt.set_subject("...");

let common_secret_key = b"secret";

// Signing JWT
let signer = HS256.signer_from_bytes(private_key)?;
let encoded_jwt = jwt.encode_with_signer(&signer)?;

// Verifing JWT. HMAC signer can also be used by verifier.
let decoded_jwt = Jwt::decode_with_verifier(&encoded_jwt, &signer)?;
```

### Signing a JWT by RSA

RSA is used to verify the integrity of a message by two keys: public and private.
Three types of RSA algorithms are available: RS256, RS384, and RS512.

You can generate the keys by executing openssl command.

```sh
# Generate a new private key. Keygen bits must be 2048 or more.
openssl openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out RSA_private.pem

# Generate a public key from the private key.
openssl pkey -in RSA_private.pem -pubout -outform PEM -out RSA_public.pem
```

```rust
use jwt_rs::{ Jwt, RS256 };

let mut jwt = Jwt::new();
jwt.set_subject("...");

// Signing JWT
let private_key = load_from_file("rsa_private.pem")?;
let signer = RS256.signer_from_private_pem(&private_key)?;
let encoded_jwt = jwt.encode_with_signer(&signer)?;

// Verifing JWT
let public_key = load_from_file("rsa_public.pem")?;
let verifier = RS256.verifier_from_public_pem(&public_key)?;
let decoded_jwt = Jwt::decode_with_verifier(&encoded_jwt, &verifier)?;
```

### Signing a JWT by RSA-PSS

RSA-PSS is used to verify the integrity of a message by two keys: public and private.

The raw key format of RSA-PSS is the same as RSA. So you should use a PKCS#8 wrapped key. It contains some optional attributes.

Three types of RSA-PSS algorithms are available: PS256, PS384, and PS512.
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
use jwt_rs::{ Jwt, PS256 };

let mut jwt = Jwt::new();
jwt.set_subject("...");

// Signing JWT
let private_key = load_from_file("rsapss_private.pem")?;
let signer = PS256.signer_from_private_pem(&private_key)?;
let encoded_jwt = jwt.encode_with_signer(&signer)?;

// Verifing JWT
let public_key = load_from_file("rsapss_public.pem")?;
let verifier = PS256.verifier_from_public_pem(&public_key)?;
let decoded_jwt = Jwt::decode_with_verifier(&encoded_jwt, &verifier)?;
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
use jwt_rs::{ Jwt, ES256 };

let mut jwt = Jwt::new();
jwt.set_subject("...");

// Signing JWT
let private_key = load_from_file("ECDSA_private.pem")?;
let signer = ES256.signer_from_private_pem(&private_key)?;
let encoded_jwt = jwt.encode_with_signer(&signer)?;

// Verifing JWT
let public_key = load_from_file("ECDSA_public.pem")?;
let verifier = ES256.verifier_from_public_pem(&public_key)?;
let decoded_jwt = Jwt::decode_with_verifier(&encoded_jwt, &verifier)?;
```

### Signing a JWT by EdDSA

EdDSA is used to verify the integrity of a message by two keys: public and private.
Types of EdDSA algorithms is only "EdDSA".
But it has two curve types: ED25519, ED448.

You can generate the keys by executing openssl command.

```sh
# Generate a new private key

# for ED25519
openssl genpkey -algorithm ED25519 -out ED25519_private.pem

# for ED448
openssl genpkey -algorithm ED448 -out ED448_private.pem

# Generate a public key from the private key.
openssl pkey -in ECDSA_private.pem -pubout -outform PEM -out ECDSA_public.pem
```

```rust
use jwt_rs::{ Jwt, EdDSA };

let mut jwt = Jwt::new();
jwt.set_subject("...");

// Signing JWT
let private_key = load_from_file("EdDSA_private.pem")?;
let signer = EdDSA.signer_from_private_pem(&private_key)?;
let encoded_jwt = jwt.encode_with_signer(&signer)?;

// Verifing JWT
let public_key = load_from_file("EdDSA_public.pem")?;
let verifier = EdDSA.verifier_from_public_pem(&public_key)?;
let decoded_jwt = Jwt::decode_with_verifier(&encoded_jwt, &verifier)?;
```

### Encrypted JWT

Not supported at this time.

### Unsecured JWT

```rust
use jwt_rs::Jwt;

let mut jwt = Jwt::new();
jwt.set_subject("...");

let encoded_jwt = jwt.encode_with_none()?;
let decoded_jwt = Jwt::decode_with_none(&encoded_jwt)?;
```

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
- [RFC8017: PKCS #1: RSA Cryptography Specifications Version 2.2](https://tools.ietf.org/html/rfc8017)
- [RFC5208: PKCS #8: Private-Key Information Syntax Specification Version 1.2](https://tools.ietf.org/html/rfc5208)
- [RFC5280: Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile](https://tools.ietf.org/html/rfc5280)
- [RFC5915: Elliptic Curve Private Key Structure](https://tools.ietf.org/html/rfc5915)
- [RFC5480: Elliptic Curve Cryptography Subject Public Key Information](https://tools.ietf.org/html/rfc5480)
- [RFC6979: Deterministic Usage of the Digital Signature Algorithm (DSA) and Elliptic Curve Digital Signature Algorithm (ECDSA)](https://tools.ietf.org/html/rfc6979)
- [RFC8410: Algorithm Identifiers for Ed25519, Ed448, X25519, and X448 for Use in the Internet X.509 Public Key Infrastructure](https://tools.ietf.org/html/rfc8410)
- [RFC7468: Textual Encodings of PKIX, PKCS, and CMS Structures](https://tools.ietf.org/html/rfc7468)

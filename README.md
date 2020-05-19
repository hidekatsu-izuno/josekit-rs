# JWS-RS

JWT (JSON Web Token) library for rust (based on OpenSSL).

## Install

```toml
[dependencies]
jwt_rs = "0.1.0"
```

This library depends on OpenSSL DLL. Read more about it [Crate openssl](https://docs.rs/openssl/0.10.29/openssl/). 

## Supported algorithms

|Name |Description                                   |
|=====|==============================================|
|HS256|HMAC using SHA-256                            |
|HS384|HMAC using SHA-384                            |
|HS512|HMAC using SHA-512                            |
|RS256|RSASSA-PKCS1-v1_5 using SHA-256               |
|RS384|RSASSA-PKCS1-v1_5 using SHA-384               |
|RS512|RSASSA-PKCS1-v1_5 using SHA-512               |
|ES256|ECDSA using P-256 and SHA-256                 |
|ES384|ECDSA using P-384 and SHA-384                 |
|ES512|ECDSA using P-521 and SHA-512                 |
|PS256|RSASSA-PSS using SHA-256 and MGF1 with SHA-256|
|PS384|RSASSA-PSS using SHA-384 and MGF1 with SHA-384|
|PS512|RSASSA-PSS using SHA-512 and MGF1 with SHA-512|
|None |No digital signature or MAC performed         |

## Supported key formats for RSA/ECDSA/RSA-PSS sigining

<table>
<tr>
    <th rowspan="2">Key type</th>
    <th rowspan="2">Encoding</th>
    <th rowspan="2">Format</th>
    <th colspan="3">Algorithm</th>
</tr>
<tr>
    <th>RSA</th>
    <th>ECDSA</th>
    <th>RSA-PSS</th>
</tr>
<tr>
    <td rowspan="4">Private key</td>
    <td rowspan="2">PKCS#8</td>
    <td>PEM</td>
    <td>OK</td>
    <td>OK</td>
    <td>OK</td>
</tr>
<tr>
    <td>DER</td>
    <td>OK</td>
    <td>OK</td>
    <td>OK</td>
</tr>
<tr>
    <td rowspan="2">PKCS#1</td>
    <td>PEM</td>
    <td>OK</td>
    <td>OK</td>
    <td>-</td>
</tr>
<tr>
    <td>DER</td>
    <td>OK</td>
    <td>OK</td>
    <td>-</td>
</tr>
<tr>
    <td rowspan="4">Public key</td>
    <td rowspan="2">PKCS#8</td>
    <td>PEM</td>
    <td>OK</td>
    <td>OK</td>
    <td>OK</td>
</tr>
<tr>
    <td>DER</td>
    <td>OK</td>
    <td>OK</td>
    <td>OK</td>
</tr>
<tr>
    <td rowspan="2">PKCS#1</td>
    <td>PEM</td>
    <td>OK</td>
    <td>-</td>
    <td>-</td>
</tr>
<tr>
    <td>DER</td>
    <td>OK</td>
    <td>-</td>
    <td>-</td>
</tr>
</table>

## Usage

### Signed JWT for HMAC

HMAC is used to verify the integrity of a message by common secret key.
Three types of HMAC algorithms are available: HS256, HS384, and HS512.
You can use any text as the key.

```rust
use jwt_rs::{ Jwt, HS256 };

let mut jwt = Jwt::new();
jwt.set_subject("user");

let common_secret_key = b"secret";

// Signing JWT
let signer = HS256.signer_from_bytes(private_key)?;
let encoded_jwt = jwt.encode_with_signer(&signer)?;

// Verifing JWT. HMAC signer can also be used by verifier.
let decoded_jwt = Jwt::decode_with_verifier(&encoded_jwt, &signer)?;
```

### Signed JWT for RSA

RSA is used to verify the integrity of a message by tow keys: public and private.
Three types of RSA algorithms are available: RS256, RS384, and RS512.
You can generate the keys by executing openssl command.

```sh
# Generate a new private key. Keygen bits must be 2048 or more.
openssl openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa_private.pem

# Generate a public key from the private key.
openssl pkey -in rsa_private.pem -pubout -outform PEM -out rsa_public.pem
```

```rust
use jwt_rs::{ Jwt, RS256 };

let mut jwt = Jwt::new();
jwt.set_subject("user");

// Signing JWT
let private_key = load_from_file("rsa_private.pem")?;
let signer = RS256.signer_from_private_pem(&private_key)?;
let encoded_jwt = from_jwt.encode_with_signer(&signer)?;

// Verifing JWT
let public_key = load_from_file("rsa_public.pem")?;
let verifier = RS256.verifier_from_public_pem(&public_key)?;
let decoded_jwt = Jwt::decode_with_verifier(&encoded_jwt, &verifier)?;
```

### Signed JWT for ECDSA

ECDSA is used to verify the integrity of a message by tow keys: public and private.
Three types of RSA algorithms are available: ES256, ES384, and ES512.
You can generate the keys by executing openssl command.

```sh
# Generate a new private key

# for ES256
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -outform PEM -out ecdsa_private.pem

# for ES384
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -outform PEM -out ecdsa_private.pem

# for ES512
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521 -outform PEM -out ecdsa_private.pem

# Generate a public key from the private key.
openssl pkey -in ecdsa_private.pem -pubout -outform PEM -out ecdsa_public.pem
```

```rust
use jwt_rs::{ Jwt, ES256 };

let mut jwt = Jwt::new();
jwt.set_subject("user");

// Signing JWT
let private_key = load_from_file("ecdsa_private.pem")?;
let signer = ES256.signer_from_private_pem(&private_key)?;
let encoded_jwt = from_jwt.encode_with_signer(&signer)?;

// Verifing JWT
let public_key = load_from_file("ecdsa_public.pem")?;
let verifier = ES256.verifier_from_public_pem(&public_key)?;
let decoded_jwt = Jwt::decode_with_verifier(&encoded_jwt, &verifier)?;
```

### Signed JWT for RSA-PSS

RSA-PSS is used to verify the integrity of a message by tow keys: public and private.
Three types of RSA-PSS algorithms are available: PS256, PS384, and PS512.
You can generate the keys by executing openssl command.

```sh
# Generate a new private key

# for PS256
openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_pss_keygen_md:sha256 -pkeyopt rsa_pss_keygen_mgf1_md:sha256 -out rsapss_private.pem

# for PS384
openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_pss_keygen_md:sha384 -pkeyopt rsa_pss_keygen_mgf1_md:sha384 -out rsapss_private.pem

# for PS512
openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_pss_keygen_md:sha512  -pkeyopt rsa_pss_keygen_mgf1_md:sha512 -out rsapss_private.pem

# Generate a public key from the private key.
openssl pkey -in rsapss_private.pem -pubout -outform PEM -out rsapss_public.pem
```

```rust
use jwt_rs::{ Jwt, PS256 };

let mut jwt = Jwt::new();
jwt.set_subject("user");

// Signing JWT
let private_key = load_from_file("rsapss_private.pem")?;
let signer = PS256.signer_from_private_pem(&private_key)?;
let encoded_jwt = from_jwt.encode_with_signer(&signer)?;

// Verifing JWT
let public_key = load_from_file("rsapss_public.pem")?;
let verifier = PS256.verifier_from_public_pem(&public_key)?;
let decoded_jwt = Jwt::decode_with_verifier(&encoded_jwt, &verifier)?;
```

### Encrypted JWT

Not supported at this time.

### Unsecured JWT

```rust
let mut jwt = Jwt::new();
jwt.set_subject("user");

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

- [RFC7519: JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)

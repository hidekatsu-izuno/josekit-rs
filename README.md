# JWS-RS

JWT (JSON Web Token) library for rust (based on OpenSSL).

## Install

```toml
[dependencies]
jwt_rs = "0.1.0"
```

This library depends on OpenSSL DLL.

## Supported algorithms

|Name |Description                       |
|=====|==================================|
|None |No signature                      |
|HS256|HMAC with SHA-256                 |
|HS384|HMAC with SHA-384                 |
|HS512|HMAC with SHA-512                 |
|RS256|RSASSA-PKCS1-v1_5 with SHA-256    |
|RS384|RSASSA-PKCS1-v1_5 with SHA-384    |
|RS512|RSASSA-PKCS1-v1_5 with SHA-512    |
|ES256|ECDSA with curve P-256 and SHA-256|
|ES384|ECDSA with curve P-384 and SHA-384|
|ES512|ECDSA with curve P-521 and SHA-512|

## Supported key formats for RSA/ECDSA sigining

<table>
<tr>
    <th>Key type</th>
    <th>Encoding</th>
    <th>Format</th>
</tr>
<tr>
    <td rowspan="4">Private key</td>
    <td rowspan="2">PKCS#8</td>
    <td>PEM</td>
</tr>
<tr>
    <td>DER</td>
</tr>
<tr>
    <td rowspan="2">PKCS#1</td>
    <td>PEM</td>
</tr>
<tr>
    <td>DER</td>
</tr>
<tr>
    <td rowspan="2">Public key</td>
    <td rowspan="2">PKCS#8</td>
    <td>PEM</td>
</tr>
<tr>
    <td>DER</td>
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
let encoded_jwt = jwt.encode_with_sign(&signer)?;

// Verifing JWT. HMAC signer can also be used by verifier.
let decoded_jwt = Jwt::decode_with_verify(&encoded_jwt, &signer)?;
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
let encoded_jwt = from_jwt.encode_with_sign(&signer)?;

// Verifing JWT
let public_key = load_from_file("rsa_public.pem")?;
let verifier = RS256.verifier_from_public_pem(&public_key)?;
let decoded_jwt = Jwt::decode_with_verify(&encoded_jwt, &verifier)?;
```

### Signed JWT for ECDSA

ECDSA is used to verify the integrity of a message by tow keys: public and private.
Three types of RSA algorithms are available: ES256, ES384, and ES512.
You can generate the keys by executing openssl command.

```sh
# Generate a new private key. A curve must have P-256.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -outform PEM -out ecdsa_private.pem

# Generate a public key from the private key.
openssl pkey -in ecdsa_private.pem -pubout -outform PEM -out ecdsa_public.pem
```

```rust
use jwt_rs::{ Jwt, RS256 };

let mut jwt = Jwt::new();
jwt.set_subject("user");

// Signing JWT
let private_key = load_from_file("ecdsa_private.pem")?;
let signer = RS256.signer_from_private_pem(&private_key)?;
let encoded_jwt = from_jwt.encode_with_sign(&signer)?;

// Verifing JWT
let public_key = load_from_file("ecdsa_public.pem")?;
let verifier = RS256.verifier_from_public_pem(&public_key)?;
let decoded_jwt = Jwt::decode_with_verify(&encoded_jwt, &verifier)?;
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

## References

- [RFC7519: JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
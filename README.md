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

### Signed JWT

```rust
use jwt-rs::jwt::Jwt;

let mut jwt = Jwt::new();
jwt.set_subject("user");

let encoded_jwt = jwt.encode_with_none()?;
let decoded_jwt = Jwt::decode_with_none(&encoded_jwt)?;
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
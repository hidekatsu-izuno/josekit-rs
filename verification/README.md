# Lean 4 specification and conformance tests

From the repository root, run the following with Cargo and Lean 4 available on
`PATH`. With Elan, Lake selects the toolchain in
[`lean-toolchain`](lean-toolchain). The specification has no external Lean
package dependencies.

```sh
./verification/check.sh
```

Mise can provide the pinned Lean and Lake release for the source proofs.

```sh
mise exec github:leanprover/lean4@4.19.0 -- ./verification/check-source.sh
```

Run `(cd verification && lake build JosekitSpec)` to check the specification
proofs, or `./verification/check-source.sh` to regenerate the Rust-derived
definitions and check their refinement proofs. `check.sh` runs the source
proofs, builds the Lean checker, and runs the opt-in Rust integration test.
It forwards additional arguments to the integration test's Cargo invocation,
so a backend can be selected with
`./verification/check.sh --no-default-features --features aws-lc-rs`.

## Contracts

| Module | Public behavior modeled | Properties proved in Lean |
| --- | --- | --- |
| [Wire](JosekitSpec/Wire.lean) | Compact framing and canonical unpadded Base64url | Successful framing preserves all segments and yields exactly three or five segments. Base64url accepts exactly the defined full and partial sextet groups with zero unused bits, using only the URL-safe alphabet. |
| [Compact](JosekitSpec/Compact.lean) | JWS signature input, JWE authenticated data, header inspection, `alg`, `kid`, `crit`, and built-in IV and tag sizes | The policy corresponds to algorithm equality, the applicable key-ID rule, and support for every listed critical name. Successful preparation preserves the original signing input or protected-header bytes. Parameter validation implements the IV and tag size rules and requires an empty encrypted key for `dir`. |
| [Compact callback flow](JosekitSpec/CompactFlow.lean) | Calls from the JWS verifier and JWE decrypter after framing and header/algorithm validation | Successful JWS verification uses the original signing input. Successful JWE processing requires the correct CEK size and successful authentication with the original protected header as AAD. Failed authentication prevents decompression and returns no plaintext. |
| [JSON serialization](JosekitSpec/JsonSerialization.lean) | Flattened and general envelopes, disjoint header fields, and external AAD | Disjointness implies that no header name occurs in both lists. External AAD contributes the dot separator even when the protected header is omitted. |
| [JWT](JosekitSpec/Jwt.lean) | Signed, unsecured and encrypted claims objects, registered claim types, and the claims validator | The executable validator implements the declarative time, audience and required-claim predicates. Expiration is exclusive, while not-before and both issued-at bounds are inclusive. Signed JWT preparation rejects the critical `b64` extension regardless of the allowlist. |
| [JWK](JosekitSpec/Jwk.lean) | JWK and JWK Set shapes, ordered key lookup, append, and first-match removal | Lookup returns exactly the keys with a matching `kid`. Append preserves lookup order and removal drops the first matching key while preserving the relative order of the others. |
| [JWK index](JosekitSpec/JwkIndex.lean) | A key list and per-`kid` buckets with separate identities for duplicate allocations | Every reachable state after any number of insertions and removals has a coherent index, and indexed lookup returns the same result as the list specification. |

The wire contracts follow the applicable sections of the JOSE standards. The
library profile allows a missing `kid` with a configured JWE decrypter and
requires it with a configured JWS verifier. Audience membership is checked
when both an expected audience and an `aud` claim are present. Required
claims must be present and equal to their configured values. JWT encoding and
decoding reject `b64` in the signed token's critical headers.
[JWS](https://www.rfc-editor.org/rfc/rfc7515.html#section-7),
[JWE](https://www.rfc-editor.org/rfc/rfc7516.html#section-7),
[JWK Set](https://www.rfc-editor.org/rfc/rfc7517.html#section-5),
[JWA](https://www.rfc-editor.org/rfc/rfc7518.html#section-5),
[JWT](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1),
[JWS unencoded payload](https://www.rfc-editor.org/rfc/rfc7797.html#section-1).

## Rust source refinement

[`rust-extract`](rust-extract/src/main.rs) parses the current Rust files with
`syn`. It matches an explicit subset of their syntax and emits Lean
definitions in Rust statement order. Unknown syntax within a translated
region causes extraction to fail. [`SourceProofs.lean`](SourceProofs.lean)
imports the freshly generated module and proves the following correspondences:

| Rust source | Quantified proof |
| --- | --- |
| `JwkSet::{new,get,push_key,remove_key}` | The projected operations refine the JWK index model. Every finite sequence starting at `new` with fresh identities for insertions has a coherent index and the same lookup results as the list specification. |
| Compact JWS authentication tail | For every byte sequence supplied as the framed segments, payload mode, decoder, and verifier, the trace and outcome agree with the byte-level model. When the decoder agrees with the Base64url model on the consumed segments, the outcome also refines the text model. |
| Compact JWE authentication tail | For every framed input and every key-unwrapping, authentication, and decompression function, the trace and outcome agree with the Compact flow model. |
| AES-GCM decryption guards and JWT header guard | The IV and tag checks pass exactly for a present 12-byte IV and a 16-byte tag. The JWT guard accepts exactly when the critical names omit `b64`. |
| JWT NumericDate conversion | Conversion succeeds only when it obtains a duration and checked addition to the epoch succeeds. For unsigned integer seconds it agrees with the Lean NumericDate reader under the target's checked-addition contract. |

The proof scope is relative to the checked syntax and its primitive
interpretations. The extractor and its Rust-to-Lean translation rules are
trusted. The JWK projection uses lists for `Vec`, a bucket function for
`BTreeMap`, and distinct identities for live `Arc` allocations. It assumes
the parallel JSON `keys` array has the state established by Rust's
constructors. JWK parsing, the `from_map` constructor, and JSON state
serialization remain outside the source proof.

The Compact tail proofs start with the framed segments and the result of
header/algorithm selection. The extractor checks the source partition,
original input slices and tail calls. Decoder correctness, Rust
JSON parsing, selector semantics, other Compact header checks, and the
cryptographic implementations are assumptions or outside the translated
regions. The code-generation rules use `Option` to model success and
failure and omit concrete error values, returned headers, allocation failure,
and compiler or FFI semantics.

## Public API conformance tests

The Lean kernel checks the theorems for the model. The Rust
[integration test](../tests/lean_conformance.rs) reports observations from
public API calls and the Lean checker computes the expected results. Cases
include repository interoperability vectors, accepted and rejected tokens,
signed and encrypted payloads, a grid of JWT time boundary cases, and a JWK
Set mutation trace. Rejection cases compare success or failure. Successful
cases compare headers, payloads, claims, or key collections as applicable.

The test checks every length-four operation sequence over two distinct keys
sharing a `kid`, including repeated insertion of equal keys. Each step
compares the index model with the Rust public API.

Recording Rust callbacks compare the call order and exact byte arguments
with the Compact flow model, including failure to unwrap or authenticate,
incorrect CEK size, and failure to decompress.

The Lean model takes cryptographic operations as callbacks. The integration
test runs the configured Rust cryptographic backend, while the Lean checker
uses reference packets and known plaintext for those operations. The Rust
conformance result is bounded by the tested inputs. JSON signature and
recipient selection order, cryptographic primitive correctness, key import
formats such as PEM and DER remain outside the proof scope.

The NumericDate model requires nonnegative dates and takes the target's
maximum duration addable to the Unix epoch as an input. The conformance
runner obtains this limit through checked `SystemTime` addition. Both sides
reject dates above the bound, including `{"exp":1e100}`. The checks include
the last representable whole second and the next second when available.
The Lean model rounds decimal fractions to nanoseconds. Rust converts
fractional JSON numbers from binary floating point, and platform-specific
time precision and fractional rounding boundaries remain outside the
refinement theorem.

#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "$0")"
lake build JosekitSpec.RustPrimitives JosekitSpec.Jwt
proof_dir="$(mktemp -d "$PWD/.lake/source-proof.XXXXXX")"
trap 'rm -rf -- "$proof_dir"' EXIT
cargo run --quiet --locked --manifest-path rust-extract/Cargo.toml \
    --target-dir "$PWD/.lake/rust-extract" -- "$PWD/.." > "$proof_dir/Extracted.lean"
lake env lean --root="$proof_dir" -DwarningAsError=true \
    -o "$proof_dir/Extracted.olean" "$proof_dir/Extracted.lean"
LEAN_PATH="$proof_dir${LEAN_PATH:+:$LEAN_PATH}" lake env lean -DwarningAsError=true SourceProofs.lean
printf '%s\n' 'Rust source extraction and Lean refinement proofs passed.'

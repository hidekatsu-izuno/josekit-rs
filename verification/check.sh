#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "$0")/.."
./verification/check-source.sh
(cd verification && lake build)
JOSEKIT_LEAN_CHECK="$PWD/verification/.lake/build/bin/josekit-check" \
    cargo test --test lean_conformance "$@" -- --ignored --nocapture

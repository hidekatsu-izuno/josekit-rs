#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "$0")/.."

pure_rust_features=aes-cbc-hmac-rustcrypto,aes-gcm-rustcrypto,aes-kw-rustcrypto,ec-rustcrypto
pure_rust_features+=,ed25519-dalek,ed448-goldilocks-plus,hmac-rustcrypto,pbkdf2-rustcrypto
pure_rust_features+=,rsa-rustcrypto,x25519-dalek,x448-goldilocks-plus

test_backend() {
    local backend=$1
    shift
    local target_dir="${CARGO_TARGET_DIR:-target}/backend-tests/$backend"

    printf '\nTesting %s\n' "$backend"
    case "$backend" in
        pure-rust)
            cargo test --target-dir "$target_dir" --no-default-features --features "$pure_rust_features" "$@"
            ;;
        aws-lc)
            cargo test --target-dir "$target_dir" --no-default-features --features aws-lc-rs "$@"
            ;;
        openssl)
            cargo test --target-dir "$target_dir" "$@"
            ;;
        libressl)
            if [[ -z ${LIBRESSL_DIR:-} ]] ||
                ! grep -Eq '^#define[[:blank:]]+LIBRESSL_VERSION_NUMBER[[:blank:]]' "$LIBRESSL_DIR/include/openssl/opensslv.h" 2>/dev/null; then
                printf 'Set LIBRESSL_DIR to a LibreSSL installation prefix with headers and libraries.\n' >&2
                return 2
            fi
            (
                unset OPENSSL_INCLUDE_DIR OPENSSL_LIB_DIR
                export OPENSSL_DIR="$LIBRESSL_DIR"
                library_path="$LIBRESSL_DIR/lib64:$LIBRESSL_DIR/lib"
                export LD_LIBRARY_PATH="$library_path${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
                export DYLD_LIBRARY_PATH="$library_path${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
                cargo test --target-dir "$target_dir" --no-default-features \
                    --features openssl,ed448-goldilocks-plus,x448-goldilocks-plus "$@"
            )
            ;;
    esac
}

selection=${1:-all}
if (( $# > 0 )); then
    shift
fi

case "$selection" in
    all)
        status=0
        for backend in pure-rust openssl libressl aws-lc; do
            test_backend "$backend" "$@" || status=1
        done
        exit "$status"
        ;;
    pure-rust|openssl|libressl|aws-lc)
        test_backend "$selection" "$@"
        ;;
    aws-lc-rs)
        test_backend aws-lc "$@"
        ;;
    *)
        printf 'Usage: %s [all|pure-rust|openssl|libressl|aws-lc] [cargo test arguments...]\n' "$0" >&2
        exit 2
        ;;
esac

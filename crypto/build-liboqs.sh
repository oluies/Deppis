#!/usr/bin/env bash
# Build a SHARED liboqs for the FFM binding (crypto/src/main/scala/crypto/Oqs.scala).
#
# Homebrew ships liboqs only as a static archive (`liboqs.a`), but Java's FFM (Panama) needs a shared
# library to `SymbolLookup.libraryLookup`. This wraps the VETTED static build (all objects) into a
# `.dylib`, linking libcrypto (liboqs' OpenSSL-backed RNG). No liboqs source is rebuilt here — the
# primitives are exactly Homebrew's audited liboqs; we only change the link form.
#
# Output: $OQS_OUT (default ~/.deppis-liboqs/liboqs.dylib — a path Oqs.scala probes; or set OQS_PATH
# to point the binding elsewhere). Requires: `brew install liboqs openssl@3`.
#
# Linux: install a shared liboqs directly (distro package or `cmake -DBUILD_SHARED_LIBS=ON` from the
# pinned OQS release) and set OQS_PATH to the resulting `liboqs.so`; this wrapper is macOS-specific.
set -euo pipefail

OQS_PREFIX="$(brew --prefix liboqs 2>/dev/null || echo /opt/homebrew/opt/liboqs)"
SSL_PREFIX="$(brew --prefix openssl@3 2>/dev/null || echo /opt/homebrew/opt/openssl@3)"
OQS_A="$OQS_PREFIX/lib/liboqs.a"
OUT="${OQS_OUT:-$HOME/.deppis-liboqs/liboqs.dylib}"

[ -f "$OQS_A" ] || { echo "liboqs static lib not found at $OQS_A — run: brew install liboqs" >&2; exit 1; }
mkdir -p "$(dirname "$OUT")"

clang -dynamiclib -install_name "$OUT" \
  -Wl,-all_load "$OQS_A" \
  -L"$SSL_PREFIX/lib" -lcrypto \
  -o "$OUT"

echo "wrote $OUT"
# Sanity: the ML-KEM/ML-DSA entry points must be exported. Capture the symbol table ONCE (piping nm
# straight into `grep -q` would SIGPIPE nm and, under pipefail, spuriously report a missing symbol).
syms="$(nm -gU "$OUT" 2>/dev/null || true)"
for sym in OQS_KEM_new OQS_KEM_encaps OQS_KEM_decaps OQS_SIG_sign OQS_SIG_verify; do
  case "$syms" in
    *"_$sym"*) ;;
    *) echo "missing symbol $sym in $OUT" >&2; exit 1 ;;
  esac
done
echo "verified ML-KEM / ML-DSA symbols present"

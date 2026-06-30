# syntax=docker/dockerfile:1
#
# Reproducible enclave build + measurement (T057, Constitution X) — Docker + Gramine SGX-sim.
#
# Stage 1 builds the obsd sidecar DETERMINISTICALLY (static musl PIE) and fails the build unless two
# independent builds in an identical path produce a byte-identical binary. Stage 2 generates the
# Gramine manifest for that binary and signs it TWICE, failing unless both signings yield the same
# MRENCLAVE (the enclave code/data measurement, which is independent of the signing key). The result
# is a reproducible MRENCLAVE exported as a build artifact.
#
# Build context = repository root:  docker build -f deploy/enclave/Dockerfile -o type=local,dest=out .
# Requires Docker only — NO SGX hardware (gramine-sgx-sign measures on any machine; only RUNNING the
# enclave needs SGX). Honest labeling (Constitution IV): a measurement produced here is DEV — it is
# signed with a throwaway dev key, not a PCK-endorsed platform key, and is not published to the public
# transparency log. It does not by itself entitle any deployment to claim metadata privacy.

# ---- Stage 1: reproducible static obsd ----
FROM rust:1.88.0-bookworm AS rbuild
ENV SOURCE_DATE_EPOCH=1700000000 CARGO_INCREMENTAL=0 CARGO_NET_RETRY=10 LC_ALL=C TZ=UTC
RUN apt-get update && apt-get install -y --no-install-recommends protobuf-compiler musl-tools \
    && rm -rf /var/lib/apt/lists/* && rustup target add x86_64-unknown-linux-musl
WORKDIR /src
# Copy ONLY the crate sources (never the local `target/`) so the build context is hermetic and the
# measurement depends solely on pinned inputs.
COPY oblivious-sidecar/Cargo.toml oblivious-sidecar/Cargo.lock oblivious-sidecar/build.rs ./
COPY oblivious-sidecar/src ./src
COPY oblivious-sidecar/proto ./proto
# Deterministic flags: locked deps, single codegen unit (no parallel-codegen ordering nondeterminism),
# no debuginfo, remapped source/cargo paths, fully static. Build twice in the SAME path (clean between)
# so the only difference between runs is wall-clock time — a true reproducibility check.
ENV RUSTFLAGS="--remap-path-prefix=/src=/build --remap-path-prefix=/usr/local/cargo=/cargo -C codegen-units=1 -C debuginfo=0 -C target-feature=+crt-static"
RUN set -eu; T=x86_64-unknown-linux-musl; \
    cargo build --release --locked --target $T --bin obsd; strip target/$T/release/obsd; \
    A=$(sha256sum target/$T/release/obsd | cut -d' ' -f1); \
    rm -rf target; \
    cargo build --release --locked --target $T --bin obsd; strip target/$T/release/obsd; \
    B=$(sha256sum target/$T/release/obsd | cut -d' ' -f1); \
    echo "OBSD_SHA_A=$A"; echo "OBSD_SHA_B=$B"; \
    test "$A" = "$B" || { echo "ERROR: obsd build is NOT reproducible"; exit 1; }; \
    echo "OBSD-REPRODUCIBLE-OK"; \
    cp target/$T/release/obsd /obsd; echo "$A" > /obsd.sha256

# ---- Stage 2: Gramine manifest + measurement ----
FROM gramineproject/gramine:stable-jammy AS measure
ENV SOURCE_DATE_EPOCH=1700000000
WORKDIR /m
COPY --from=rbuild /obsd /obsd
COPY --from=rbuild /obsd.sha256 /obsd.sha256
COPY deploy/enclave/obsd.manifest.template .
# A throwaway DEV signing key (random per build). MRENCLAVE is independent of the key, so it stays
# reproducible; only MRSIGNER depends on the key (in production the signer is the PCK-endorsed key).
RUN gramine-sgx-gen-private-key --force
RUN set -eu; \
    for d in a b; do mkdir -p $d; \
      gramine-manifest obsd.manifest.template $d/obsd.manifest; \
      gramine-sgx-sign --manifest $d/obsd.manifest --output $d/obsd.manifest.sgx >$d/sign.log 2>&1; \
      # Anchor extraction to the `Measurement:` section (the hex is on the line AFTER the label), so a
      # trusted-file SHA-256 or other digest elsewhere in the log can never be mistaken for MRENCLAVE.
      grep -iA1 'Measurement:' $d/sign.log | grep -oiE '[0-9a-f]{64}' | head -1 > $d/mr.hex; \
    done; \
    test -s a/mr.hex && test "$(wc -c < a/mr.hex)" -eq 65; \
    echo "MRENCLAVE_A=$(cat a/mr.hex)"; echo "MRENCLAVE_B=$(cat b/mr.hex)"; \
    test "$(cat a/mr.hex)" = "$(cat b/mr.hex)" || { echo "ERROR: MRENCLAVE not reproducible"; exit 1; }; \
    echo "MRENCLAVE-REPRODUCIBLE-OK"; \
    cp a/mr.hex /mrenclave.hex
    # (MRSIGNER is the throwaway dev key's hash — a dev value, not exported; in production it is the
    #  PCK-endorsed platform signer. MRENCLAVE above is key-independent and is the reproducible value.)

FROM scratch AS out
COPY --from=measure /mrenclave.hex /mrenclave.hex
COPY --from=measure /obsd.sha256 /obsd.sha256

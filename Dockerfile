# jam-lean-target: the jam-lean model of JAM (Gray Paper v0.8.0) as a fuzzer target.
# Standard target packaging (jam-fuzzing fuzz-proto/README.md): JAM_FUZZ, JAM_FUZZ_SPEC,
# JAM_FUZZ_DATA_PATH and JAM_FUZZ_SOCK_PATH.
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates git clang && rm -rf /var/lib/apt/lists/*
RUN curl -sSfL https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y --default-toolchain none
ENV PATH=/root/.elan/bin:$PATH
WORKDIR /src
COPY lean-toolchain lakefile.lean lake-manifest.json ./
RUN lake update --keep-toolchain 2>/dev/null || true
COPY . .
RUN lake build jam-lean-target

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends socat libgmp10 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/.lake/build/bin/jam-lean-target /usr/local/bin/jam-lean-target
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY data/bls12-381-srs-2-11-uncompressed-zcash.bin /usr/local/share/jam-lean-target/srs.bin
ENV JAM_LEAN_SRS=/usr/local/share/jam-lean-target/srs.bin
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

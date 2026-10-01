#!/bin/sh
# hook-repro pipeline for recipe rshooks-0.2.3: `rshooks build` (tequdev/rshooks-build
# 0.2.3) of the crate at $CRATE, offline, from the source's own Cargo.lock ($LOCK) vendored
# at /vendor. Output: entry $ENTRY (<index>.<fn>) and its metadata.json sidecar.
set -eu
TC=/usr/local/rustup/toolchains/1.89.0-aarch64-unknown-linux-gnu
export SOURCE_DATE_EPOCH=0 TZ=UTC LC_ALL=C
export PATH=$TC/bin:/opt/rshooks/bin:/usr/sbin:/usr/bin:/sbin:/bin
export CARGO=$TC/bin/cargo RUSTC=$TC/bin/rustc HOME=/work/home CARGO_HOME=/work/cargo-home
export CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 CARGO_TERM_COLOR=never CARGO_TARGET_DIR=/work/target
export RUSTFLAGS="--remap-path-prefix=/work/src/= --remap-path-prefix=/vendor/= --remap-path-prefix=/work/cargo-home/=cargo-home/"
[ "$(rustc -V)" = "rustc 1.89.0 (29483883e 2025-08-04)" ] || { echo "rustc mismatch: $(rustc -V)" >&2; exit 5; }
[ "$(rshooks --version)" = "rshooks 0.2.3" ] || { echo "rshooks-build mismatch" >&2; exit 5; }
rm -rf /work/src && mkdir -p /work/src "$HOME" "$CARGO_HOME" && cp -R /src/. /work/src/
cd /work/src
CRATE=${CRATE:-.}; LOCK=${LOCK:-Cargo.lock}
[ -f "$CRATE/Cargo.toml" ] || { echo "no Cargo.toml at CRATE=$CRATE" >&2; exit 4; }
if find . -path '*/.cargo/config*' -type f -exec grep -l rustflags {} + | grep -q .; then
  echo "source sets rustflags in .cargo/config; refusing (RUSTFLAGS would override them)" >&2; exit 6; fi
printf '[source.crates-io]\nreplace-with = "vendored"\n[source.vendored]\ndirectory = "/vendor"\n[net]\noffline = true\n' > "$CARGO_HOME/config.toml"
WS=$(cargo locate-project --workspace --offline --manifest-path "$CRATE/Cargo.toml" --message-format plain)
[ "$(dirname "$WS")/Cargo.lock" -ef "$LOCK" ] || { echo "LOCK=$LOCK is not the workspace lockfile of $CRATE" >&2; exit 4; }
rshooks build --manifest-path "$CRATE/Cargo.toml" --out /work/rsout > /work/rshooks.log 2>&1 || { cat /work/rshooks.log >&2; exit 7; }
cd /work/rsout/current
if [ -n "${ENTRY:-}" ]; then E=$ENTRY; else
  N=$(ls *.wasm | wc -l | tr -d ' ')
  [ "$N" = 1 ] || { echo "crate declares $N entries; set ENTRY=<index>.<fn>" >&2; exit 8; }
  E=$(basename *.wasm .wasm); fi
[ -f "$E.wasm" ] && [ -f "$E.metadata.json" ] || { echo "no entry $E in $(ls)" >&2; exit 8; }
cp "$E.wasm" /out/hook.wasm
cp "$E.metadata.json" /out/hook.metadata.json
{
  echo "crate: $CRATE"; echo "lock: $LOCK"; echo "entry: $E"
  echo "rustc_version: $(rustc -V)"; echo "cargo_version: $(cargo -V)"; echo "rshooks_build_version: $(rshooks --version)"
  echo "RUSTFLAGS: $RUSTFLAGS"
  echo "--- entries (file bytes sha512half)"
  for f in *.wasm; do printf '%s %s %s\n' "$f" "$(wc -c < "$f" | tr -d ' ')" "$(sha512sum "$f" | cut -c1-64)"; done
  echo "--- rshooks build log"; cat /work/rshooks.log
} > /out/build.txt

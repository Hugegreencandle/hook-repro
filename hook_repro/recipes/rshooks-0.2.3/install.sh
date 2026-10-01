#!/bin/sh
# Image-build step for recipe rshooks-0.2.3, run as `RUN --network=none`: every input is
# a sha256-pinned artifact already in /tc. Adds the wasm32v1-none std to the image's
# rustc 1.89.0 and installs rshooks-build 0.2.3 from its own Cargo.lock, offline.
set -eu
TC=/usr/local/rustup/toolchains/1.89.0-aarch64-unknown-linux-gnu
[ "$($TC/bin/rustc -V)" = "rustc 1.89.0 (29483883e 2025-08-04)" ] || { echo "unexpected rustc" >&2; exit 5; }
cp -R /tc/rustlib-wasm32v1-none "$TC/lib/rustlib/wasm32v1-none"
export PATH=$TC/bin:/usr/sbin:/usr/bin:/sbin:/bin SOURCE_DATE_EPOCH=0 TZ=UTC LC_ALL=C
export CARGO_HOME=/tmp/rshooks-install-home CARGO_BUILD_JOBS=1 CARGO_TERM_COLOR=never
mkdir -p "$CARGO_HOME"
printf '[source.crates-io]\nreplace-with = "vendored"\n[source.vendored]\ndirectory = "/tc/vendor"\n[net]\noffline = true\n' > "$CARGO_HOME/config.toml"
cargo install --locked --offline -j 1 --path /tc/rshooks-build-0.2.3 --root /opt/rshooks
[ "$(/opt/rshooks/bin/rshooks --version)" = "rshooks 0.2.3" ] || { /opt/rshooks/bin/rshooks --version >&2; exit 5; }
rm -rf "$CARGO_HOME" /tc/vendor /tc/rshooks-build-0.2.3

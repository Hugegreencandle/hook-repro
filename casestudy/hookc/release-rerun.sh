#!/bin/sh
# Release re-run of the public case study (hookc 0.5.0 + portable paths in manifests and reports).
# Regenerates the ClaimReward sidecars (the hookc-llvm22 recipe digests changed with the recipe-text
# neutralisation), reproduces each from git, verifies ClaimReward against Xahau mainnet (two operators),
# re-runs the three xhc-bin127 preset verifies of casestudy/claimreward/ and the bind-review demo.
# Network use: Xahau JSON-RPC reads only (xahau.network, cluster.cbotlabs.xyz) plus the pinned toolchain
# downloads on a cold cache. Run from anywhere; every path it records is relative to the repo root.
# Usage: casestudy/hookc/release-rerun.sh [path to a clone of Ekiserrepe/cron-claimreward-xahau]
set -u
cd "$(dirname "$0")/../.." || exit 1
C=casestudy/hookc
O=$C/release
CR=${1:-${HOOK_REPRO_CACHE:-$HOME/.cache/hook-repro}/src/cron-claimreward-xahau}
CRREV=0a10b61b4f361384395a00ebc56e585f8389627f
H=805351CE26FB79DA00647CEFED502F7E15C2ACCCE254F11DEFEDDCE241F8E9CA
[ -d "$CR" ] || git clone -q https://github.com/Ekiserrepe/cron-claimreward-xahau "$CR" || exit 1
rm -rf "$O" && mkdir -p "$O"
run() { # name cmd...
  n=$1; shift
  "$@" > "$O/$n.out" 2> "$O/$n.err"; rc=$?
  echo "$n exit=$rc" | tee -a "$O/exit-codes.txt"
}
for d in claimreward claimreward-llvm22; do rm -rf "${C:?}/$d"; done

run build-claimreward ./hookc build --git "$CR" --rev $CRREV --toolchain xhc-bin127 --preset classic \
    --on Cron --can-emit ClaimReward --out "$C/claimreward"
run build-claimreward-llvm22 ./hookc build --git "$CR" --rev $CRREV --toolchain hookc-llvm22 --platform all \
    --entry claimReward.c --on Cron --can-emit ClaimReward --out "$C/claimreward-llvm22"

run reproduce-claimreward ./hookc reproduce --metadata "$C/claimreward/0.hook.metadata.json" --git "$CR" \
    --wasm tests/fixtures/claimreward_onledger.wasm
# no --platform: every twin in builder.platforms_built is rebuilt (re-checks that claim)
run reproduce-claimreward-llvm22-all ./hookc reproduce --metadata "$C/claimreward-llvm22/0.hook.metadata.json" --git "$CR"

run verify-claimreward-mainnet ./hook-repro verify --hookhash $H \
    --git "$CR" --metadata "$C/claimreward/0.hook.metadata.json" --network xahau-mainnet --out "$O/verify-claimreward"

# casestudy/claimreward/: the vendored source against the three Hooks Builder presets (classic reproduces;
# the two Builder pipelines are expected MISMATCH, exit 2: they are not the toolchain the hook was built with)
for p in classic builder-2025 builder-2026-07; do
  t=$(echo $p | tr -d -); rm -rf "casestudy/claimreward/verify-$t"
  run verify-src-$t ./hook-repro verify --hookhash $H --src casestudy/claimreward/src --recipe xhc-bin127 \
      --preset $p --network xahau-mainnet --out "casestudy/claimreward/verify-$t"
  cp "$O/verify-src-$t.out" "casestudy/claimreward/verify-$t.txt"
done

# bind-review demo over the classic verify report (the bound document is a stub, NOT a review)
run bind-claimreward ./hook-repro bind-review casestudy/claimreward/bind-demo.md --hookhash $H \
    --network xahau-mainnet --verify-report casestudy/claimreward/verify-classic/verify-report.json \
    --out casestudy/claimreward/binding.json
# a --network that is not the report's network is NOT BOUND (exit 3)
run bind-claimreward-wrong-network ./hook-repro bind-review casestudy/claimreward/bind-demo.md --hookhash $H \
    --network xahau-testnet --verify-report casestudy/claimreward/verify-classic/verify-report.json

for d in claimreward claimreward-llvm22; do
  shasum -a 256 "$C/$d/0.hook.wasm" "$C/$d/0.hook.metadata.json"
done > "$O/sha256.txt"
./hook-repro recipes > "$O/recipes.txt"

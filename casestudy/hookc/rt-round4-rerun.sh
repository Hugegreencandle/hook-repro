#!/bin/sh
# Public release: the steps for a private-source testnet hook were removed from this script; the remaining steps are unchanged.
# Re-run of the hookc case study after the RT round 4 fixes (branch fix/rt-round4, hookc 0.5.0,
# xhc-bin127 date defines, fixed --no-wce reason, --src byte check, repo config check). Regenerates the
# sidecars (schema version and the xhc-bin127 recipe digest changed), reproduces each from git, and verifies ClaimReward (mainnet, two operators) and
# [a private-source testnet hook removed for the public release] against the chain. Network use: Xahau JSON-RPC
# reads only. Writes casestudy/hookc/{claimreward,claimreward-llvm22}/ and
# casestudy/hookc/rt-round4/*.txt. Usage: casestudy/hookc/rt-round4-rerun.sh
set -u
HR=$(cd "$(dirname "$0")/../.." && pwd)
C=$HR/casestudy/hookc
O=$C/rt-round4
CR=$HOME/.cache/hook-repro/src/cron-claimreward-xahau
CRREV=0a10b61b4f361384395a00ebc56e585f8389627f
mkdir -p "$O"
run() { # name cmd...
  n=$1; shift
  "$@" > "$O/$n.out" 2> "$O/$n.err"; rc=$?
  echo "$n exit=$rc" | tee -a "$O/exit-codes.txt"
}
: > "$O/exit-codes.txt"
for d in claimreward claimreward-llvm22; do rm -rf "${C:?}/$d"; done

run build-claimreward "$HR/hookc" build --git "$CR" --rev $CRREV --toolchain xhc-bin127 --preset classic \
    --on Cron --can-emit ClaimReward --out "$C/claimreward"
run build-claimreward-llvm22 "$HR/hookc" build --git "$CR" --rev $CRREV --toolchain hookc-llvm22 --platform all \
    --entry claimReward.c --on Cron --can-emit ClaimReward --out "$C/claimreward-llvm22"

run reproduce-claimreward "$HR/hookc" reproduce --metadata "$C/claimreward/0.hook.metadata.json" --git "$CR" \
    --wasm "$HR/tests/fixtures/claimreward_onledger.wasm"
# no --platform: every twin in builder.platforms_built is rebuilt (re-checks that claim)
run reproduce-claimreward-llvm22-all "$HR/hookc" reproduce --metadata "$C/claimreward-llvm22/0.hook.metadata.json" --git "$CR"
for p in linux/arm64 linux/amd64; do
  t=$(echo $p | tr / -)
  run reproduce-claimreward-llvm22-$t "$HR/hookc" reproduce --metadata "$C/claimreward-llvm22/0.hook.metadata.json" --git "$CR" --platform $p
done

run verify-claimreward-mainnet "$HR/hook-repro" verify --hookhash 805351CE26FB79DA00647CEFED502F7E15C2ACCCE254F11DEFEDDCE241F8E9CA \
    --git "$CR" --metadata "$C/claimreward/0.hook.metadata.json" --network xahau-mainnet --out "$O/verify-claimreward"

for d in claimreward claimreward-llvm22; do
  shasum -a 256 "$C/$d/0.hook.wasm" "$C/$d/0.hook.metadata.json"
done | sed "s|$HR/||" > "$O/sha256.txt"

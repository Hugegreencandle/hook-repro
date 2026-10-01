#!/bin/sh
# R3-05: a RELATIVE path escapes /work/src into the jail's own root file system, which is the
# per-arch pinned base image (arm64 vs amd64 python:3.12-slim). The lexical pre-scan only refuses
# ABSOLUTE operands, so __has_include("../../usr/lib/aarch64-linux-gnu/libc.so.6") makes the twins
# build different bytes. Consequence with R3-03: a single-twin build + forged platforms_built passes
# `verify` (no re-check, no caveat) though the amd64 twin demonstrably builds OTHER bytes.
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=$RT/../rt3-hookc; W=$RT/work-r3-05; rm -rf "$W"; mkdir -p "$W/repo"
cd "$W/repo" && git init -q && git config user.email rt@x && git config user.name rt
cat > hook.c <<'C'
#include <stdint.h>
extern int32_t _g(uint32_t id, uint32_t maxiter);
extern int64_t accept(uint32_t read_ptr, uint32_t read_len, int64_t error_code);
#if __has_include("../../usr/lib/aarch64-linux-gnu/libc.so.6")
#define LIMIT 1000000
#else
#define LIMIT 10
#endif
int64_t hook(uint32_t reserved) { _g(1, 1); return accept(0, 0, LIMIT); }
C
git add . && git commit -qm h && cd "$RT"
"$HR/hookc" build --git "$W/repo" --toolchain hookc-llvm22 --platform all --no-wce --out "$W/all" > "$W/all.out" 2> "$W/all.err"
echo "build --platform all exit=$?"; grep -m1 -o "CROSS-PLATFORM MISMATCH[^\\]*" "$W/all.err" | cut -c1-200
"$HR/hookc" build --git "$W/repo" --toolchain hookc-llvm22 --platform linux/arm64 --out "$W/o" > "$W/o.out" 2> "$W/o.err"
echo "build --platform linux/arm64 exit=$?"
python3 - "$W/o/0.hook.metadata.json" "$W/forged.metadata.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["builder"]["platforms_built"] = ["linux/amd64", "linux/arm64"]
open(sys.argv[2], "w").write(json.dumps(d, indent=2, ensure_ascii=False) + "\n")
PY
"$HR/hookc" reproduce --metadata "$W/forged.metadata.json" --git "$W/repo" > "$W/r.out" 2>&1
echo "reproduce (all claimed twins) exit=$?"; grep -m2 "VERDICT\|reason" "$W/r.out" | cut -c1-220
python3 "$RT/stub_verify.py" "$HR" "$W/o/0.hook.wasm" "$W/forged.metadata.json" --git "$W/repo" --platform linux/arm64 > "$W/v.out" 2> "$W/v.err"
grep "VERDICT\|reason\|verify exit" "$W/v.out" | cut -c1-400

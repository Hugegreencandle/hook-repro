#!/bin/sh
# R3-05 variant (RT3 fix session): the per-arch probe hidden in a macro (not seen by the pre-scan).
# The twins build different bytes; an arm64-only build + forged platforms_built must not pass
# reproduce or verify (chain read SIMULATED by stub_verify.py). Run against $HR (default ../rt3-hookc).
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=${HR:-$RT/../rt3-hookc}; W=$RT/work-r3-05m; rm -rf "$W"; mkdir -p "$W/repo"
cd "$W/repo" && git init -q && git config user.email rt@x && git config user.name rt
cat > hook.c <<'C'
#include <stdint.h>
extern int32_t _g(uint32_t id, uint32_t maxiter);
extern int64_t accept(uint32_t read_ptr, uint32_t read_len, int64_t error_code);
#define STR(x) #x
#define XSTR(x) STR(x)
#define LIBC ../../usr/lib/aarch64-linux-gnu/libc.so.6
#if __has_include(XSTR(LIBC))
#define LIMIT 1000000
#else
#define LIMIT 10
#endif
int64_t hook(uint32_t reserved) { _g(1, 1); return accept(0, 0, LIMIT); }
C
git add . && git commit -qm h && cd "$RT"
"$HR/hookc" build --git "$W/repo" --toolchain hookc-llvm22 --platform all --no-wce --out "$W/all" > "$W/all.out" 2>&1
echo "build --platform all exit=$? $(grep -m1 -o 'CROSS-PLATFORM MISMATCH[^\\]*' "$W/all.out" | cut -c1-160)"
"$HR/hookc" build --git "$W/repo" --toolchain hookc-llvm22 --platform linux/arm64 --out "$W/o" > "$W/o.out" 2>&1
echo "build --platform linux/arm64 exit=$?"
python3 - "$W/o/0.hook.metadata.json" "$W/forged.metadata.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["builder"]["platforms_built"] = ["linux/amd64", "linux/arm64"]
open(sys.argv[2], "w").write(json.dumps(d, indent=2, ensure_ascii=False) + "\n")
PY
"$HR/hookc" reproduce --metadata "$W/forged.metadata.json" --git "$W/repo" > "$W/r.out" 2>&1; rc=$?
echo "reproduce (all claimed twins) exit=$rc $(grep -m1 VERDICT "$W/r.out")"
python3 "$RT/stub_verify.py" "$HR" "$W/o/0.hook.wasm" "$W/forged.metadata.json" --git "$W/repo" > "$W/v.out" 2> "$W/v.err"
grep "VERDICT\|verify exit" "$W/v.out" | cut -c1-200; grep -m1 "^reason" "$W/v.out" | cut -c1-260
python3 "$RT/stub_verify.py" "$HR" "$W/o/0.hook.wasm" "$W/forged.metadata.json" --git "$W/repo" --platform linux/arm64 > "$W/v1.out" 2> "$W/v1.err"
echo "--- verify --platform linux/arm64:"; grep "VERDICT\|verify exit\|platforms_built_rechecked" "$W/v1.out" | cut -c1-200

#!/bin/sh
# R3-04a: a second `hookc reproduce --out D` sees run 1's outputs in /out (never emptied) -> the
# source's __has_include("../../out/hook.wasm") flips -> run 1 MISMATCH, run 2 REPRODUCED.
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=$RT/../rt3-hookc; W=$RT/work-r3-04a; rm -rf "$W"; mkdir -p "$W/repo"
cd "$W/repo" && git init -q && git config user.email rt@x && git config user.name rt
cat > hook.c <<'C'
#include <stdint.h>
extern int32_t _g(uint32_t id, uint32_t maxiter);
extern int64_t accept(uint32_t read_ptr, uint32_t read_len, int64_t error_code);
#if __has_include("../../out/hook.wasm")
#define V 2
#else
#define V 1
#endif
int64_t hook(uint32_t reserved) { _g(1, 1); return accept(0, 0, V); }
C
git add . && git commit -qm h && cd "$RT"
# attacker: build twice into the same --out; the 2nd build's sidecar is for V=2 bytes
"$HR/hookc" build --git "$W/repo" --toolchain hookc-llvm22 --platform linux/arm64 --no-wce --out "$W/o" > /dev/null 2>&1
H1=$(python3 -c "import json;print(json.load(open('$W/o/0.hook.metadata.json'))['HookHash'])")
"$HR/hookc" build --git "$W/repo" --toolchain hookc-llvm22 --platform linux/arm64 --no-wce --out "$W/o" > /dev/null 2>&1
echo "attacker 2nd build exit=$?"
H2=$(python3 -c "import json;print(json.load(open('$W/o/0.hook.metadata.json'))['HookHash'])")
echo "clean-build HookHash $H1 ; same-out rebuild HookHash $H2 (sidecar now claims this for commit $(git -C "$W/repo" rev-parse --short HEAD))"
M="$W/o/0.hook.metadata.json"
"$HR/hookc" reproduce --metadata "$M" --git "$W/repo" --no-wce > "$W/c.out" 2>&1; echo "control fresh out: exit=$?"; grep -m1 VERDICT "$W/c.out"
for n in 1 2; do
  "$HR/hookc" reproduce --metadata "$M" --git "$W/repo" --no-wce --out "$W/rev" > "$W/r$n.out" 2>&1; echo "reviewer run $n --out rev: exit=$?"; grep -m2 "VERDICT\|reason" "$W/r$n.out"
done

#!/bin/sh
# F1: xhc-bin127 (clang 15) ignores SOURCE_DATE_EPOCH: __DATE__ is the container's wall-clock date.
# The double build passes (same day), hookc writes a sidecar, and the bytes embed the build DAY.
# Control: hookc-llvm22 (clang 22) honours SOURCE_DATE_EPOCH=0 ("Jan  1 1970").
set -u
HR=<repo>; S=$(cd "$(dirname "$0")" && pwd); W=$S/work-f1; rm -rf "$W"; mkdir -p "$W/repo"
cd "$W/repo"; git init -q; git config user.email rt@x; git config user.name rt
cat > hook.c <<'C'
#include "hookapi.h"
int64_t hook(uint32_t r) {
    _g(1,1);
    static const char d[] = "BUILT[" __DATE__ "]";
    return accept(SBUF(d), 0);
}
C
git add -A; git commit -qm init
echo "host date: $(date -u)"
"$HR/hookc" build --git "$W/repo" --toolchain xhc-bin127 --out "$W/xhc" >"$W/xhc.out" 2>"$W/xhc.err"; echo "xhc-bin127 build exit=$?"
strings "$W/xhc/0.hook.wasm" | grep BUILT
python3 -c "import json;d=json.load(open('$W/xhc/0.hook.metadata.json'));print('sidecar HookHash',d['HookHash'],'env',d['builder']['env'])"
"$HR/hookc" reproduce --metadata "$W/xhc/0.hook.metadata.json" --git "$W/repo" >"$W/xhc.rep" 2>&1; echo "xhc-bin127 reproduce (same day) exit=$?"; head -1 "$W/xhc.rep"
"$HR/hookc" build --git "$W/repo" --toolchain hookc-llvm22 --platform linux/arm64 --no-wce --out "$W/llvm" >"$W/llvm.out" 2>"$W/llvm.err"; echo "hookc-llvm22 build exit=$?"
strings "$W/llvm/0.hook.wasm" | grep BUILT

#!/bin/sh
# F1b: __TIME__ / __TIMESTAMP__ on both C toolchains (does the double build fail closed?)
set -u
HR=<repo>; S=$(cd "$(dirname "$0")" && pwd); W=$S/work-f1b; rm -rf "$W"; mkdir -p "$W/repo"
cd "$W/repo"; git init -q; git config user.email rt@x; git config user.name rt
cat > hook.c <<'C'
#include "hookapi.h"
int64_t hook(uint32_t r) {
    _g(1,1);
    static const char d[] = "TS[" __TIME__ "|" __TIMESTAMP__ "]";
    return accept(SBUF(d), 0);
}
C
git add -A; git commit -qm init
"$HR/hookc" build --git "$W/repo" --toolchain hookc-llvm22 --platform linux/arm64 --no-wce --out "$W/llvm" >/dev/null 2>"$W/llvm.err"; echo "hookc-llvm22 build exit=$?"
strings "$W/llvm/0.hook.wasm" 2>/dev/null | grep TS; for b in 1 2; do strings "$W/llvm/builds/linux-arm64/build$b/hook.wasm" 2>/dev/null| grep TS; done; tail -c 300 "$W/llvm.err"; echo
"$HR/hookc" build --git "$W/repo" --toolchain xhc-bin127 --no-wce --out "$W/xhc" >/dev/null 2>"$W/xhc.err"; echo "xhc-bin127 build exit=$?"
for b in 1 2; do strings "$W/xhc/builds/linux-amd64/build$b/hook.wasm" 2>/dev/null | grep TS; done; tail -c 200 "$W/xhc.err"; echo

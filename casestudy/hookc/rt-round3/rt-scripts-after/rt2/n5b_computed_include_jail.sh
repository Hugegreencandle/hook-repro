#!/bin/sh
# N5b (fix check): the N5 probe with a MACRO-COMPUTED operand, which the lexical pre-scan cannot
# see, so only the jail stands between the compiler and the host. Also a computed #include of
# /proc/version. Expected on the fixed code: the __has_include probe is false on both twins
# (LIMIT 10 = HookHash FA5FA332...), and the /proc include fails to build (exit 3).
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=$RT/../rt2-hookc; W=$RT/work-n5b; rm -rf "$W"; mkdir -p "$W"
mk() { mkdir -p "$1"; cd "$1"; git init -q; git config user.email rt@x; git config user.name rt; cat > hook.c; git add -A; git commit -qm c; cd - >/dev/null; }
mk "$W/sys" <<'C'
#include "hookapi.h"
#define S(x) #x
#define XS(x) S(x)
#define D sys
#if __has_include(XS(/D/devices/system/cpu/cpu0/cpu_capacity))
#define LIMIT 1000000   /* host kernel file visible */
#else
#define LIMIT 10
#endif
int64_t hook(uint32_t r) { _g(1,1); return accept(0, 0, LIMIT); }
C
mk "$W/proc" <<'C'
#include "hookapi.h"
#define S(x) #x
#define XS(x) S(x)
#define P proc
#include XS(/P/version)
int64_t hook(uint32_t r) { _g(1,1); return accept(0, 0, 10); }
C
"$HR/hookc" build --git "$W/sys" --toolchain hookc-llvm22 --platform all --no-wce --out "$W/out-sys" >"$W/sys.json" 2>"$W/sys.log"; echo "computed __has_include(/sys/...) build (both twins) exit=$?"
python3 -c "import json;d=json.load(open('$W/out-sys/0.hook.metadata.json'));print('  HookHash',d['HookHash'],'(FA5FA332... = LIMIT 10: host file NOT visible)' if d['HookHash'].startswith('FA5FA332') else '(host file visible)', 'platforms_built', d['builder'].get('platforms_built'))" 2>/dev/null || tail -3 "$W/sys.log"
"$HR/hookc" build --git "$W/proc" --toolchain hookc-llvm22 --platform linux/arm64 --no-wce --out "$W/out-proc" >"$W/proc.json" 2>"$W/proc.log"; echo "computed #include </proc/version> build exit=$?"; grep -o "fatal error: [^;]*" "$W/proc.log" | head -1

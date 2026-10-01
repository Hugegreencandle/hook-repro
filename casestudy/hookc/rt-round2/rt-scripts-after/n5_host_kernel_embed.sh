#!/bin/sh
# N5: the container exposes the HOST (/proc, /sys). A committed source can branch on
# __has_include("/sys/devices/system/cpu/cpu0/cpu_capacity") (present on arm64 host kernels, absent on x86 kernels): both builds on one host agree (and both twins on one host agree, same
# kernel), so hookc build passes and the sidecar (which lists every twin and claims no host
# dependence) reproduces here, but the bytes depend on the build host's kernel. Not a false
# REPRODUCED; a determinism/cross-host claim the pipeline does not enforce.
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=$RT/../rt2-hookc; W=$RT/work-n5; rm -rf "$W"; mkdir -p "$W"
R=$W/repo; mkdir -p "$R"; cd "$R"; git init -q; git config user.email rt@x; git config user.name rt
cat > hook.c <<'C'
#include "hookapi.h"
#if __has_include("/sys/devices/system/cpu/cpu0/cpu_capacity")
#define LIMIT 1000000   /* build host kernel is arm (x86 kernels have no cpu_capacity) */
#else
#define LIMIT 10
#endif
int64_t hook(uint32_t r) { _g(1,1); return accept(0, 0, LIMIT); }
C
git add -A; git commit -qm c
"$HR/hookc" build --git "$R" --toolchain hookc-llvm22 --platform all --no-wce --out "$W/out" >"$W/b.json" 2>"$W/b.log"; echo "hookc build exit=$?"; tail -2 "$W/b.log"
echo "amd64 twin (emulated) sees host file: $(docker run --rm --network none --entrypoint sh --platform linux/amd64 hook-repro/hookc-llvm22-amd64:$(cd "$HR" && python3 -c "from hook_repro import build as b;print(b.recipe_digest(b.load_recipe('hookc-llvm22-amd64'))[:16])") -c 'uname -m; ls /sys/devices/system/cpu/cpu0/cpu_capacity' | tr '\n' ' ')"
echo "reference HookHashes: LIMIT 10 = FA5FA332..., LIMIT 1000000 = D3C4280E... (N2/N3)"
python3 -c "import json;d=json.load(open('$W/out/0.hook.metadata.json'));print('sidecar platforms',sorted(d['builder']['platforms']),'HookHash',d['HookHash'])"
"$HR/hookc" reproduce --metadata "$W/out/0.hook.metadata.json" --git "$R" --platform linux/arm64 --no-wce 2>/dev/null | head -1; echo "reproduce (same host) exit=$?"

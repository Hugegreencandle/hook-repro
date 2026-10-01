#!/bin/sh
# R3-04b: same as R3-04 through `hook-repro verify --metadata --out DIR` (the chain read is SIMULATED
# by stub_verify.py; everything else is the unmodified CLI). verify builds into DIR/build1, DIR/build2,
# which the jailed compiler reaches as ../../out/ ; a file committed OUTSIDE source.vcs.path at
# vout/build{1,2}/payload.h becomes part of the "rebuild of git <commit>:hook".
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=$RT/../rt3-hookc; W=$RT/work-r3-04b; rm -rf "$W"; mkdir -p "$W/repo/hook"
cd "$W/repo" && git init -q && git config user.email rt@x && git config user.name rt
cat > hook/hook.c <<'C'
#include <stdint.h>
extern int32_t _g(uint32_t id, uint32_t maxiter);
extern int64_t accept(uint32_t read_ptr, uint32_t read_len, int64_t error_code);
#if __has_include("../../out/payload.h")
#include "../../out/payload.h"
#else
#define PAYLOAD 0
#endif
int64_t hook(uint32_t reserved) { _g(1, 1); return accept(0, 0, PAYLOAD); }
C
for b in build1 build2; do mkdir -p vout/$b; echo '#define PAYLOAD 0x31337' > vout/$b/payload.h; done
git add . && git commit -qm "hook + unrelated files" && cd "$RT"
for b in build1 build2; do mkdir -p "$W/o/builds/linux-arm64/$b"; cp "$W/repo/vout/$b/payload.h" "$W/o/builds/linux-arm64/$b/"; done
"$HR/hookc" build --git "$W/repo" --path hook --toolchain hookc-llvm22 --platform linux/arm64 --out "$W/o" > "$W/build.out" 2> "$W/build.err"
echo "attacker build exit=$?"
git clone -q "$W/repo" "$W/checkout"
cd "$W/checkout"
echo "--- control: verify without --out"
python3 "$RT/stub_verify.py" "$HR" "$W/o/0.hook.wasm" "$W/o/0.hook.metadata.json" --src . 2>/dev/null | grep "VERDICT\|reason\|verify exit" | cut -c1-300
echo "--- verify --out vout (inside the checkout)"
python3 "$RT/stub_verify.py" "$HR" "$W/o/0.hook.wasm" "$W/o/0.hook.metadata.json" --src . --out vout 2>/dev/null | grep "VERDICT\|reason\|verify exit" | cut -c1-400

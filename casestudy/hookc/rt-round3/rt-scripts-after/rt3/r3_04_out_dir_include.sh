#!/bin/sh
# R3-04: the jailed compiler can read the host --out directory. run_container bind-mounts the
# (possibly pre-existing, never emptied) out dir read-write at /jail/out; from cwd /work/src the
# RELATIVE include "../../out/<f>" is /out/<f>. The pre-scan only refuses ABSOLUTE paths.
# (a) same --out reused: 1st reproduce MISMATCH, 2nd reproduce REPRODUCED (bytes a clean build of the
#     commit does not produce).
# (b) --out inside the reviewed checkout: a file committed OUTSIDE source.vcs.path steers the bytes;
#     first run REPRODUCED (exit 0). Without --out (fresh tmp): MISMATCH.
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=$RT/../rt3-hookc; W=$RT/work-r3-04; rm -rf "$W"; mkdir -p "$W/repo/hook"
cd "$W/repo" && git init -q && git config user.email rt@x && git config user.name rt
cat > hook/hook.c <<'C'
#include <stdint.h>
extern int32_t _g(uint32_t id, uint32_t maxiter);
extern int64_t accept(uint32_t read_ptr, uint32_t read_len, int64_t error_code);
#if __has_include("../../out/payload.h")
#include "../../out/payload.h"
#else
#define PAYLOAD 0            /* what a reviewer of commit:hook believes is built */
#endif
int64_t hook(uint32_t reserved) { _g(1, 1); return accept(0, 0, PAYLOAD); }
C
# payload committed OUTSIDE the stated path "hook", at the out dir the README-style command will use
for b in build1 build2; do mkdir -p repro/linux-arm64/$b; echo '#define PAYLOAD 0x31337' > repro/linux-arm64/$b/payload.h; done
git add . && git commit -qm "hook + unrelated files" && cd "$RT"
# attacker build: payload present in the builder's out dir
for b in build1 build2; do mkdir -p "$W/o/builds/linux-arm64/$b"; cp "$W/repo/repro/linux-arm64/$b/payload.h" "$W/o/builds/linux-arm64/$b/"; done
"$HR/hookc" build --git "$W/repo" --path hook --toolchain hookc-llvm22 --platform linux/arm64 --no-wce --out "$W/o" \
   > "$W/build.out" 2> "$W/build.err"; echo "attacker build exit=$?"
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print('sidecar', d['HookHash'], d['source']['vcs'])" "$W/o/0.hook.metadata.json"
M="$W/o/0.hook.metadata.json"
echo "--- control: reproduce with a fresh tmp out dir"
"$HR/hookc" reproduce --metadata "$M" --git "$W/repo" --no-wce > "$W/c.out" 2>&1; echo "exit=$?"; grep -m2 "VERDICT\|reason" "$W/c.out"
echo "--- (a) reviewer reuses one --out dir: run 1 then run 2"
"$HR/hookc" reproduce --metadata "$M" --git "$W/repo" --no-wce --out "$W/rev-out" > "$W/a1.out" 2>&1; echo "run1 exit=$?"; grep -m1 VERDICT "$W/a1.out"
# nothing the attacker did between runs; run 1 left hook.wasm etc. The payload variant needs payload.h,
# so (a) is shown with a __has_include("../../out/hook.wasm") twin below.
echo "--- (b) reviewer works inside the checkout: --src . --out repro"
git clone -q "$W/repo" "$W/checkout"
( cd "$W/checkout" && "$HR/hookc" reproduce --metadata "$M" --src . --no-wce --out repro > "$W/b.out" 2>&1; echo "exit=$?" )
grep -m2 "VERDICT\|reason" "$W/b.out"

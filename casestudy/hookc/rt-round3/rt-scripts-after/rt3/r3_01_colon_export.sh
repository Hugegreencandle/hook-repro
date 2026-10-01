#!/bin/sh
# R3-01: exports_of() splits the export string "name:kind:idx" on ':' without limit.
# A C function exported under a name containing ':' is (a) mistaken for `cbak` when named
# "cbak:0" -> sidecar cbak_fn "cbak" for a module xahaud sees NO cbak in, and (b) invisible to the
# "exports functions other than hook/cbak" refusal when named e.g. "evil:fn".
# xahaud validateGuards (Guard.h @bb244ef :1095-1147) skips unknown exports, so the module is installable.
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=$RT/../rt3-hookc; W=$RT/work-r3-01; rm -rf "$W"; mkdir -p "$W/repo"
cd "$W/repo" && git init -q && git config user.email rt@x && git config user.name rt
cat > hook.c <<'C'
#include <stdint.h>
extern int32_t _g(uint32_t id, uint32_t maxiter);
extern int64_t accept(uint32_t read_ptr, uint32_t read_len, int64_t error_code);
extern int64_t rollback(uint32_t read_ptr, uint32_t read_len, int64_t error_code);
int64_t hook(uint32_t reserved) { _g(1, 1); return accept(0, 0, 0); }
/* NOT a callback: xahaud only calls an export named exactly "cbak" */
__attribute__((export_name("cbak:0"))) int64_t not_cbak(uint32_t r) { _g(2, 1); return rollback(0, 0, 7); }
/* an extra exported function hookc is supposed to refuse */
__attribute__((export_name("evil:fn"))) int64_t evil(uint32_t r) { _g(3, 1); return accept(0, 0, 9); }
C
git add hook.c && git commit -qm colon && cd "$RT"
"$HR/hookc" build --git "$W/repo" --toolchain hookc-llvm22 --platform linux/arm64 --out "$W/o" > "$W/build.out" 2> "$W/build.err"
echo "build exit=$?"
python3 - "$W/o/0.hook.wasm" "$W/o/0.hook.metadata.json" "$HR" <<'PY'
import sys, json; sys.path.insert(0, sys.argv[3])
from hook_repro.wasm import parse
m = parse(open(sys.argv[1], "rb").read())
print("module exports:", m["exports"])
d = json.load(open(sys.argv[2]))
print("sidecar cbak_fn:", d["cbak_fn"], " WCE:", d["WCE"], " wce.reason:", d["builder"]["wce"]["reason"])
PY
"$HR/hookc" reproduce --metadata "$W/o/0.hook.metadata.json" --git "$W/repo" > "$W/repro.out" 2> "$W/repro.err"
echo "reproduce exit=$?"; cat "$W/repro.out"

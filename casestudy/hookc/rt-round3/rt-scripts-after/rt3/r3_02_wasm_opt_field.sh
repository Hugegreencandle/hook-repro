#!/bin/sh
# R3-02: builder.wasm_opt = any("wasm-opt" in c for c in commands). The clang command line lists the
# source file names, so a top-level source named wasm-opt.c makes wasm_opt true on a build where
# wasm-opt never ran (xhc-bin127, STAGES=clean). The field is regenerated identically -> REPRODUCED.
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=$RT/../rt3-hookc; W=$RT/work-r3-02; rm -rf "$W"; mkdir -p "$W/repo"
cd "$W/repo" && git init -q && git config user.email rt@x && git config user.name rt
cat > wasm-opt.c <<'C'
#include <stdint.h>
extern int32_t _g(uint32_t id, uint32_t maxiter);
extern int64_t accept(uint32_t read_ptr, uint32_t read_len, int64_t error_code);
int64_t hook(uint32_t reserved) { _g(1, 1); return accept(0, 0, 0); }
C
git add . && git commit -qm w && cd "$RT"
"$HR/hookc" build --git "$W/repo" --toolchain xhc-bin127 --param CLANG_OPT=-O2 --param WASMOPT=-O2 --param STAGES=clean \
   --out "$W/o" > "$W/build.out" 2> "$W/build.err"; echo "build exit=$?"; tail -3 "$W/build.err"
python3 -c "
import json,sys; d=json.load(open(sys.argv[1])); b=d['builder']
print('builder.wasm_opt =', b['wasm_opt']); print('builder.commands =', b['commands']); print('params =', b['params'])
" "$W/o/0.hook.metadata.json"
"$HR/hookc" reproduce --metadata "$W/o/0.hook.metadata.json" --git "$W/repo" > "$W/repro.out" 2> "$W/repro.err"
echo "reproduce exit=$?"; cat "$W/repro.out"

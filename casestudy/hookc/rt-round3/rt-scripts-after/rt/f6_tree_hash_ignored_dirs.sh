#!/bin/sh
# F6: hashing.TREE_IGNORE_DIRS (.git, __pycache__, .hook-repro) are skipped by tree_sha256 at ANY depth, but
# every pipeline does `cp -R /src/. /work/src/`, so files in them are compiled. Two trees with the SAME
# tree_sha256 (the metadata/manifest/bind-review "source identity") build DIFFERENT bytes.
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=$RT/../rt-hookc; W=$RT/work-f6; rm -rf "$W"; mkdir -p "$W"
for v in A B; do
  mkdir -p "$W/$v/__pycache__"
  printf '#include "hookapi.h"\n#include "__pycache__/cfg.h"\nint64_t hook(uint32_t r) { _g(1,1); return accept(0, 0, LIMIT); }\n' > "$W/$v/hook.c"
done
printf '#define LIMIT 10\n' > "$W/A/__pycache__/cfg.h"
printf '#define LIMIT 1000000\n' > "$W/B/__pycache__/cfg.h"
for v in A B; do
  "$HR/hook-repro" build "$W/$v" --recipe hookc-llvm22 --preset deploy --out "$W/out$v" > "$W/$v.json" 2>"$W/$v.log"; echo "$v build exit=$?"
  python3 -c "import json;d=json.load(open('$W/$v.json'));print('$v tree_sha256',d['source_tree_sha256'],'HookHash',d['output']['sha512half'])"
done

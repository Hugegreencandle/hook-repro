#!/bin/sh
# hook-repro pipeline for recipe kvt-llvm22 (KVT build_deploy.sh, originally developed for an internal project; containerised).
# clang -Oz -> wasm-opt pass list -> wasm-strip -> guard_hoist.py -> wasm-validate.
set -eu
export SOURCE_DATE_EPOCH=0 TZ=UTC LC_ALL=C
export PATH=/tc/llvm/bin:/tc/binaryen/bin:/tc/wabt/bin:$PATH LD_LIBRARY_PATH=/tc/lib
rm -rf /work/src && mkdir -p /work/src && cp -R /src/. /work/src/
cd /work/src
# Source files are positional parameters, passed after `--` and never word-split or globbed:
# ENTRY, or every top-level *.c in C-locale byte order. Only plain names are accepted.
set --
if [ -n "${ENTRY:-}" ]; then
  set -- "$ENTRY"
else
  N=$(find . -maxdepth 1 -type f -name '*.c' -exec printf x \; | wc -c | tr -d ' ')
  LIST=$(find . -maxdepth 1 -type f -name '*.c' | sed 's|^\./||' | LC_ALL=C sort)
  while IFS= read -r f; do [ -z "$f" ] || set -- "$@" "$f"; done <<EOF_LIST
$LIST
EOF_LIST
  [ "$#" -eq "$N" ] || { echo "top-level .c file names do not list cleanly ($# of $N)" >&2; exit 4; }
fi
[ "$#" -gt 0 ] || { echo "no top-level .c files in source dir" >&2; exit 4; }
for f in "$@"; do
  case "$f" in
    -*|*[!A-Za-z0-9._+-]*) echo "unsafe source file name: $f" >&2; exit 4 ;;
  esac
  [ -f "./$f" ] || { echo "source is not a regular top-level file: $f" >&2; exit 4; }
done
J=/work/stages.txt; : > $J
stage() { printf '%s %s %s\n' "$1" "$(wc -c < "$2" | tr -d ' ')" "$(sha512sum "$2" | cut -c1-64)" >> $J; }
O=/work/out.wasm
CLANG_FLAGS="--target=wasm32-unknown-unknown-wasm -Oz -nostdlib -ffreestanding -Wno-int-conversion -ffile-prefix-map=/work/src/= -mno-bulk-memory -Wl,--no-entry -Wl,--allow-undefined -Wl,--export=hook -Wl,--export-if-defined=cbak -I/hdr -o $O"
CLANG_CMD="clang $CLANG_FLAGS -- $*"  # the build log's record only; never executed as a string
clang $CLANG_FLAGS -- "$@"; stage clang $O
WO="--inlining-optimizing --always-inline-max-function-size 1000000 --shrink-level=100000000 --coalesce-locals-learning --vacuum --merge-blocks --merge-locals --flatten --ignore-implicit-traps -ffm --const-hoisting --code-folding --code-pushing --dae-optimizing --dce --simplify-globals-optimizing --simplify-locals-nonesting --reorder-locals --rereloop --precompute-propagate --local-cse --remove-unused-brs --memory-packing -c --avoid-reinterprets -Oz"
WASM_OPT_RAN=0
wasm-opt $O -o $O $WO; stage opt $O; WASM_OPT_RAN=1  # set only after wasm-opt exited 0 (set -e)
wasm-strip $O; stage strip $O
python3 /tc/guard_hoist.py $O $O >/work/hoist.log 2>&1; stage hoist $O
wasm-validate $O
cp $O /out/hook.wasm
{
  echo "sources: $*"
  echo "clang_version: $(clang --version | head -1)"
  echo "wasm_opt_version: $(wasm-opt --version)"
  echo "wabt_version: $(wasm-strip --version 2>/dev/null || echo 1.0.41)"
  echo "HOOKC_WASM_OPT_RAN=$WASM_OPT_RAN"  # hookc reads builder.wasm_opt from this line only
  echo "--- commands"; echo "$CLANG_CMD"; echo "wasm-opt $WO"; echo "wasm-strip"; echo "python3 guard_hoist.py"; echo "wasm-validate"
  echo "--- stages"; cat $J
} > /out/build.txt

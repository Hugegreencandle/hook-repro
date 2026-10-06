#!/bin/sh
# hook-repro pipeline for recipe buildbox-2026-10 (live hook-buildbox.xrpl.org C pipeline,
# matched byte-for-byte 2026-10-06). Same pinned binaries as xhc-bin127. Differences from xhc-bin127:
#  - /tc is on PATH during the clang link, so the clang 15 driver runs `/tc/wasm-opt <out> -O3 -o <out>`
#    itself after wasm-ld (as in the server image, where wasm-opt is /usr/bin/wasm-opt). This hidden
#    stage is why every PATH-less rebuild of a Builder hook differed.
#  - the server's fixed settings: clang -O3, ONE explicit wasm-opt pass (fixed pass list + -O3), hook-cleaner.
#    The request's "-O2"/"-Os" option does not change the output.
# Runs inside a --network none container. Inputs: /src (ro), params via env (allowlists on the host).
# Output: /out/hook.wasm, /out/build.txt.
# clang(link + implicit wasm-opt -O3) -> wasm-opt LIST -O3 -> hook-cleaner -> guard_checker (check only).
set -eu
export SOURCE_DATE_EPOCH=0 TZ=UTC LC_ALL=C
S=/tc/wasi-sdk
L="--shrink-level=100000000 --coalesce-locals-learning --vacuum --merge-blocks --merge-locals --flatten --ignore-implicit-traps -ffm --const-hoisting --code-folding --code-pushing --dae-optimizing --dce --simplify-globals-optimizing --simplify-locals-nonesting --reorder-locals --rereloop --precompute-propagate --local-cse --remove-unused-brs --memory-packing -c --avoid-reinterprets -O3"
case "$WASMOPT" in builder2025) WO="$L" ;; none) WO="" ;; *) WO="$WASMOPT" ;; esac

rm -rf /work/src && mkdir -p /work/src && cp -R /src/. /work/src/
cd /work/src
# Source files are positional parameters, passed after `--` and never word-split or globbed:
# ENTRY, or every top-level *.c in C-locale byte order. Only plain names are accepted.
set --
N=$(find . -maxdepth 1 -type f -name '*.c' -exec printf x \; | wc -c | tr -d ' ')
LIST=$(find . -maxdepth 1 -type f -name '*.c' | sed 's|^\./||' | LC_ALL=C sort)
while IFS= read -r f; do [ -z "$f" ] || set -- "$@" "$f"; done <<EOF_LIST
$LIST
EOF_LIST
[ "$#" -eq "$N" ] || { echo "top-level .c file names do not list cleanly ($# of $N)" >&2; exit 4; }
[ "$#" -gt 0 ] || { echo "no top-level .c files in source dir" >&2; exit 4; }
for f in "$@"; do
  case "$f" in
    -*|*[!A-Za-z0-9._+-]*) echo "unsafe source file name: $f" >&2; exit 4 ;;
  esac
  [ -f "./$f" ] || { echo "source is not a regular top-level file: $f" >&2; exit 4; }
done

J=/work/stages.txt; : > $J
stage() { printf '%s %s %s\n' "$1" "$(wc -c < "$2" | tr -d ' ')" "$(sha512sum "$2" | cut -c1-64)" >> $J; }

case "$CLANG_OPT" in -O0|-O1|-O2|-O3|-Os|-Oz) ;; *) echo "bad CLANG_OPT" >&2; exit 4 ;; esac
CLANG_FLAGS="$CLANG_OPT --sysroot=$S/share/wasi-sysroot -xc -ffile-prefix-map=/work/src/= -fdiagnostics-print-source-range-info -Werror=implicit-function-declaration --no-standard-libraries -nostartfiles -Wl,--allow-undefined,--no-entry,--export-all -o /work/out.wasm -I/hdr"
# clang 15 ignores SOURCE_DATE_EPOCH (clang honours it from 16 on): __DATE__/__TIME__/__TIMESTAMP__ would
# embed the build's wall-clock time (RT4 F1). They are defined to exactly what clang >= 16 gives for
# SOURCE_DATE_EPOCH=0 (the hookc-llvm22/kvt-llvm22 pipelines), so no build embeds a date or time.
D1='-D__DATE__="Jan  1 1970"' D2='-D__TIME__="00:00:00"' D3='-D__TIMESTAMP__="Thu Jan  1 00:00:00 1970"'
CLANG_CMD="$S/bin/clang -Wno-builtin-macro-redefined $D1 $D2 $D3 $CLANG_FLAGS -- $*"  # the build log's record only; never executed as a string
# The driver's own post-link wasm-opt: ask the driver (-###) whether it will run it, record that line.
DRV=$(PATH=/tc:$PATH $S/bin/clang -### -Wno-builtin-macro-redefined "$D1" "$D2" "$D3" $CLANG_FLAGS -- "$@" 2>&1 | grep '"/tc/wasm-opt"' || true)
PATH=/tc:$PATH $S/bin/clang -Wno-builtin-macro-redefined "$D1" "$D2" "$D3" $CLANG_FLAGS -- "$@"
stage clang /work/out.wasm
CMDS="PATH=/tc:\$PATH $CLANG_CMD"
WASM_OPT_RAN=0  # 1 only once a wasm-opt stage has actually executed (set -e)
if [ -n "$DRV" ]; then
  WASM_OPT_RAN=1
  CMDS="$CMDS
(clang driver, after wasm-ld) /tc/wasm-opt <out> -O3 -o <out>"
else
  echo "clang driver did not schedule /tc/wasm-opt after the link; this is not the buildbox pipeline" >&2; exit 4
fi
n=0
for st in $(echo "$STAGES" | tr ',' ' '); do
  n=$((n+1))
  case "$st" in
    opt)
      if [ -n "$WO" ]; then
        mv /work/out.wasm /work/unopt.wasm
        /tc/wasm-opt $WO -o /work/out.wasm /work/unopt.wasm
        WASM_OPT_RAN=1
        stage "opt$n" /work/out.wasm; CMDS="$CMDS
/tc/wasm-opt $WO"
      fi ;;
    clean)
      /tc/hook-cleaner /work/out.wasm >/work/clean.log 2>&1
      stage "clean$n" /work/out.wasm; CMDS="$CMDS
/tc/hook-cleaner" ;;
    *) echo "bad stage $st" >&2; exit 4 ;;
  esac
done
if /tc/guard_checker /work/out.wasm >/work/guard.log 2>&1; then G=pass; else G=fail; fi
cp /work/out.wasm /out/hook.wasm
{
  echo "sources: $*"
  echo "guard_checker: $G"
  echo "clang_version: $($S/bin/clang --version | head -1)"
  echo "wasm_opt_version: $(/tc/wasm-opt --version)"
  echo "HOOKC_WASM_OPT_RAN=$WASM_OPT_RAN"  # hookc reads builder.wasm_opt from this line only
  echo "--- commands"; echo "$CMDS"
  echo "--- stages"; cat $J
} > /out/build.txt
[ "$G" = pass ] || { echo "guard_checker rejected the output:" >&2; cat /work/guard.log >&2; exit 5; }

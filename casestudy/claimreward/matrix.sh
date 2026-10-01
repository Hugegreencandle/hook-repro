S=/tc/wasi-sdk
L="--shrink-level=100000000 --coalesce-locals-learning --vacuum --merge-blocks --merge-locals --flatten --ignore-implicit-traps -ffm --const-hoisting --code-folding --code-pushing --dae-optimizing --dce --simplify-globals-optimizing --simplify-locals-nonesting --reorder-locals --rereloop --precompute-propagate --local-cse --remove-unused-brs --memory-packing -c --avoid-reinterprets"
T=$(sha512sum /src/target.wasm | cut -c1-64)
cd /tmp; mkdir -p w; cd w
for CO in -O0 -O1 -O2 -O3 -Os -Oz; do
 $S/bin/clang $CO --sysroot=$S/share/wasi-sysroot -xc -Werror=implicit-function-declaration --no-standard-libraries -nostartfiles -Wl,--allow-undefined,--no-entry,--export-all /src/claimReward.c -o c.wasm -I/hdr 2>/dev/null || continue
 for WO in none "$L -O3" "$L -O2" "$L -Os" "$L -Oz" -O1 -O2 -O3 -O4 -Os -Oz; do
  for ORDER in oc oco; do
   cp c.wasm x.wasm
   [ "$WO" != none ] && /tc/wasm-opt $WO -o x.wasm c.wasm
   /tc/hook-cleaner x.wasm >/dev/null 2>&1
   [ $ORDER = oco ] && [ "$WO" != none ] && { cp x.wasm y.wasm; /tc/wasm-opt $WO -o x.wasm y.wasm; }
   H=$(sha512sum x.wasm | cut -c1-64); SZ=$(wc -c < x.wasm)
   M=""; [ "$H" = "$T" ] && M=MATCH
   echo "$CO|$(echo $WO | awk '{print ($1 ~ /shrink/)?"LIST"$NF:$0}')|$ORDER|$SZ|$M"
  done
 done
done

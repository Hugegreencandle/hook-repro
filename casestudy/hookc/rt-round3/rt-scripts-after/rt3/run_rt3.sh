#!/bin/sh
# RT round 3 re-run against ../rt3-hookc = the FIXED repo (fix/rt-round1 after the RT3 fixes). Serial; docker needed; R3-03 reads Xahau testnet.
cd "$(dirname "$0")"
for s in r3_01_colon_export r3_02_wasm_opt_field r3_03_verify_platforms_built r3_04a_out_dir_rerun r3_04_out_dir_include r3_04b_verify_out_dir r3_05_twin_divergence r3_06_jail_probe r3_08_crash_paths; do
  echo "### $s"; sh ./$s.sh > $s.raw 2>&1; rc=$?; grep -v INF $s.raw > $s.out; echo "script exit=$rc"  # rc of the script, not of grep
done
W=$PWD python3 r3_07_git_reader_edges.py > r3_07.out 2>&1

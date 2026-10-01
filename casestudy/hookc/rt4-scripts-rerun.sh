#!/bin/sh
# Re-run every RT round-4 reproducer (scratchpad/rt4/f*.sh) against the fixed code. Each script is copied
# unchanged except HR (the red team's worktree -> this checkout) into a scratch run dir (its work-* dirs stay
# out of the repo); stdout+stderr of each go to casestudy/hookc/rt-round4/rt4-scripts-after/<name>.out and
# its exit code to exit-codes.txt. Usage: rt4-scripts-rerun.sh RT4_DIR RUN_DIR
set -u
HR=$(cd "$(dirname "$0")/../.." && pwd)
RT4=$1; RUN=$2
OUT=$HR/casestudy/hookc/rt-round4/rt4-scripts-after
mkdir -p "$OUT" "$RUN"; : > "$OUT/exit-codes.txt"
cp "$RT4/stub_verify.py" "$RUN/"
for f in f2_dirty_src_worktree f1_build_date f1b_timestamp f3_wce_unavailable_is_mismatch f3b_null_wce_reason_host_specific f4_bind_drops_caveats; do
  sed "s|^HR=\$HR_RT4;|HR=$HR;|" "$RT4/$f.sh" > "$RUN/$f.sh"
  cp "$RUN/$f.sh" "$OUT/$f.sh"
  sh "$RUN/$f.sh" > "$OUT/$f.out" 2>&1; rc=$?
  echo "$f exit=$rc" >> "$OUT/exit-codes.txt"
done

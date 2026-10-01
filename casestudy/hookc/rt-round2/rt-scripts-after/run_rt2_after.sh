#!/bin/sh
# Re-run every RT round-2 repro against the fixed code (../rt2-hookc = fix/rt-round1 HEAD).
cd "$(dirname "$0")"
echo "rt2-hookc at $(git -C ../rt2-hookc rev-parse --short HEAD)"
for s in n1_replace_objects_e2e n1_replace_export n1b_planted_tree_object n2_filename_flag_injection n3_ident_worktree_divergence n5_host_kernel_embed n5b_computed_include_jail n6_platforms_not_built; do
  echo "### $s"; sh ./$s.sh > $s.after.out 2>&1; echo "script exit=$?"
done
for s in n4_definition_hookon n7_timeout_crash; do
  echo "### $s"; python3 ./$s.py > $s.after.out 2>&1; echo "script exit=$?"
done

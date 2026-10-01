#!/bin/sh
# Re-run every RT round-1 and round-2 repro against the FIXED repo (fix/rt-round1 after the RT3 fixes).
cd "$(dirname "$0")"
echo "target $(git -C rt-hookc rev-parse --short HEAD)"
cd rt
for s in fp1_fp2_unchecked_source_fields fp3_verify_ignores_metadata fp4_worktree_provenance fp5_casefold_export fp6_preset_label f6_tree_hash_ignored_dirs fn1_autocrlf c1_export_path_escape c2_non_utf8_name; do
  echo "### rt/$s"; sh ./$s.sh > $s.after-rt3.out 2>&1; echo "script exit=$?"
done
for s in l1_fetch_selfreported_node l2_cache_trusted compat_roundtrip; do
  echo "### rt/$s"; python3 ./$s.py > $s.after-rt3.out 2>&1; echo "script exit=$?"
done
cd ../rt2
for s in n1_replace_objects_e2e n1_replace_export n1b_planted_tree_object n1c_evil_sidecar_after_fix n2_filename_flag_injection n3_ident_worktree_divergence n5_host_kernel_embed n5b_computed_include_jail n6_platforms_not_built; do
  echo "### rt2/$s"; sh ./$s.sh > $s.after-rt3.out 2>&1; echo "script exit=$?"
done
for s in n4_definition_hookon n7_timeout_crash; do
  echo "### rt2/$s"; python3 ./$s.py > $s.after-rt3.out 2>&1; echo "script exit=$?"
done

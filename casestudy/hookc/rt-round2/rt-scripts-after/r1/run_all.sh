#!/bin/sh
cd "$(dirname "$0")"
for s in c1_export_path_escape c2_non_utf8_name fp1_fp2_unchecked_source_fields fp3_verify_ignores_metadata fp4_worktree_provenance fp5_casefold_export fp6_preset_label f6_tree_hash_ignored_dirs fn1_autocrlf; do
  echo "### $s" ; sh ./$s.sh > $s.after.out 2>&1; echo "script exit=$?"
done
for s in l1_fetch_selfreported_node l2_cache_trusted compat_roundtrip; do
  echo "### $s"; python3 ./$s.py > $s.after.out 2>&1; echo "script exit=$?"
done

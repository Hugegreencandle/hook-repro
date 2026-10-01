#!/bin/sh
# F2: `hookc reproduce --src WORKTREE` / `hook-repro verify --src WORKTREE` accept a work tree whose files
# differ from HEAD (skip-worktree edit: `git status` is clean) and say REPRODUCED. The reviewer reads the
# benign work-tree file; the bytes come from the committed (different) blob. hookc refuses checkout-
# converting .gitattributes for exactly this reason (N3) but does not check the --src work tree itself.
set -u
HR=<repo>; S=$(cd "$(dirname "$0")" && pwd); W=$S/work-f2; rm -rf "$W"; mkdir -p "$W/repo"
cd "$W/repo"; git init -q; git config user.email rt@x; git config user.name rt
cat > hook.c <<'C'
#include "hookapi.h"
int64_t hook(uint32_t r) {
    _g(1,1);
    return accept(0, 0, 666);   /* COMMITTED: accepts everything */
}
C
git add -A; git commit -qm init
"$HR/hookc" build --git "$W/repo" --toolchain hookc-llvm22 --platform linux/arm64 --out "$W/o" >/dev/null 2>"$W/b.err"; echo "build exit=$?"
# what the reviewer is handed: same repo, work-tree file edited, hidden from status by skip-worktree
cat > hook.c <<'C'
#include "hookapi.h"
int64_t hook(uint32_t r) {
    _g(1,1);
    return rollback(0, 0, 1);   /* WORK TREE: rejects everything */
}
C
git update-index --skip-worktree hook.c
echo "git status --porcelain: [$(git status --porcelain)]"
echo "work tree vs HEAD blob:"; git show HEAD:hook.c | diff - hook.c
"$HR/hookc" reproduce --metadata "$W/o/0.hook.metadata.json" --src "$W/repo" >"$W/r.out" 2>"$W/r.err"; echo "hookc reproduce --src exit=$?"; cat "$W/r.out"
python3 "$S/stub_verify.py" "$HR" "$W/o/0.hook.wasm" "$W/o/0.hook.metadata.json" --src "$W/repo" --out "$W/v" 2>/dev/null | grep -E "VERDICT|exit="
# plain dirty edit (no skip-worktree) is also accepted
git update-index --no-skip-worktree hook.c; echo "status now: [$(git status --porcelain)]"
"$HR/hookc" reproduce --metadata "$W/o/0.hook.metadata.json" --src "$W/repo" >"$W/r2.out" 2>&1; echo "hookc reproduce --src (visibly dirty) exit=$?"; head -1 "$W/r2.out"

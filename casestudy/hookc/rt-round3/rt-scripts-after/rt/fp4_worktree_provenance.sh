#!/bin/sh
# FP4: `hookc build <dir>` derives provenance with `git status --porcelain --ignored=no` and never binds the
# built content to the commit: (a) a gitignored extra top-level .c and (b) a skip-worktree edit are compiled
# but the metadata says commit X, dirty:false. `hookc reproduce --src <dir>` then says REPRODUCED;
# a clean export of commit X builds DIFFERENT bytes.
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=$RT/../rt-hookc; W=$RT/work-fp4; rm -rf "$W"; mkdir -p "$W"
R=$W/repo; mkdir -p "$R"; cd "$R"; git init -q; git config user.email rt@x; git config user.name rt
cat > hook.c <<'C'
#include "hookapi.h"
__attribute__((weak)) const int64_t LIMIT = 10;   /* reviewed value */
int64_t hook(uint32_t r) { _g(1,1); return accept(0, 0, LIMIT); }
C
printf '*_local.c\n' > .gitignore
git add -A && git commit -qm init && X=$(git rev-parse HEAD)
TC="--toolchain hookc-llvm22 --platform linux/arm64"
"$HR/hookc" build --git "$R" --rev $X $TC --out "$W/honest" >/dev/null 2>"$W/honest.log"; echo "honest --git build: $(python3 -c "import json;print(json.load(open('$W/honest/0.hook.metadata.json'))['HookHash'])")"
# (a) gitignored top-level .c overriding the weak constant
printf 'const long long LIMIT = 1000000;\n' > "$R/zz_local.c"
echo "git status (a): [$(git -C "$R" status --porcelain)]"
"$HR/hookc" build "$R" $TC --out "$W/a" >/dev/null 2>"$W/a.log"; echo "build exit=$?"
python3 -c "import json;d=json.load(open('$W/a/0.hook.metadata.json'));print('(a) metadata HookHash',d['HookHash'],'vcs',d['source']['vcs'])"
"$HR/hookc" reproduce --metadata "$W/a/0.hook.metadata.json" --src "$R" --platform linux/arm64 2>/dev/null; echo "reproduce --src exit=$?"
"$HR/hookc" reproduce --metadata "$W/a/0.hook.metadata.json" --git "$R" --platform linux/arm64 >"$W/a-git.out" 2>&1; echo "reproduce --git exit=$? ($(tail -1 "$W/a-git.out" | cut -c1-120))"
rm "$R/zz_local.c"
# (b) skip-worktree edit of a tracked file
sed -i '' 's/= 10;/= 99999;/' "$R/hook.c"; git -C "$R" update-index --skip-worktree hook.c
echo "git status (b): [$(git -C "$R" status --porcelain)]"
"$HR/hookc" build "$R" $TC --out "$W/b" >/dev/null 2>"$W/b.log"; echo "build exit=$?"
python3 -c "import json;d=json.load(open('$W/b/0.hook.metadata.json'));print('(b) metadata HookHash',d['HookHash'],'vcs',d['source']['vcs'])"
"$HR/hookc" reproduce --metadata "$W/b/0.hook.metadata.json" --src "$R" --platform linux/arm64 2>/dev/null; echo "reproduce --src exit=$?"

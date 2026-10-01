#!/bin/sh
# N3 (LOW): a committed .gitattributes `ident` makes every CHECKOUT of hook.c differ from the blob
# hookc compiles. The work tree a reviewer reads (and passes as --src) says sizeof(id)==47 -> 10;
# the compiled blob has "$Id$" (sizeof 5) -> 1000000. REPRODUCED from that --src work tree.
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=$RT/../rt2-hookc; W=$RT/work-n3; rm -rf "$W"; mkdir -p "$W"
R=$W/repo; mkdir -p "$R"; cd "$R"; git init -q; git config user.email rt@x; git config user.name rt
printf 'hook.c ident\n' > .gitattributes
cat > hook.c <<'C'
#include "hookapi.h"
static const char id[] = "$Id$";
int64_t hook(uint32_t r) { _g(1,1); return accept(0, 0, sizeof(id) == 5 ? 1000000 : 10); }
C
git add -A; git commit -qm c; rm hook.c; git checkout -- hook.c
echo "work tree (what a reviewer reads): $(grep 'char id' hook.c)"
echo "git blob (what is compiled):        $(git cat-file -p HEAD:hook.c | grep 'char id')"
echo "git status: [$(git status --porcelain)]"
TC="--toolchain hookc-llvm22 --platform linux/arm64 --no-wce"
"$HR/hookc" build "$R" $TC --out "$W/out" >/dev/null 2>"$W/b.log"; echo "hookc build <worktree> exit=$?"
"$HR/hookc" reproduce --metadata "$W/out/0.hook.metadata.json" --src "$R" --platform linux/arm64 --no-wce 2>/dev/null; echo "reproduce --src <worktree> exit=$?"
mkdir "$W/asread"; cp "$R/hook.c" "$W/asread/"
"$HR/hookc" build "$W/asread" $TC --allow-unversioned --out "$W/out-asread" >/dev/null 2>&1; echo "build of the work-tree text exit=$?"
python3 -c "import json;a=json.load(open('$W/out/0.hook.metadata.json'))['HookHash'];b=json.load(open('$W/out-asread/0.hook.metadata.json'))['HookHash'];print('sidecar HookHash',a);print('work-tree text  ',b,'(differs)' if a!=b else '(same)')"

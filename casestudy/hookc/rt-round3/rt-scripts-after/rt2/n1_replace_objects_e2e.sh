#!/bin/sh
# N1 FALSE-POSITIVE: git replace refs. Sidecar names the GENUINE commit C and GENUINE tree T
# (the ids a reviewer checks / a signature covers), yet the compiled bytes come from a replacement
# tree T'. `hookc reproduce --src <that repo>` (and --git <that repo>) say REPRODUCED, exit 0.
# A clean clone of the same commit (refs/replace not fetched) gives MISMATCH.
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=$RT/../rt2-hookc; W=$RT/work-n1; rm -rf "$W"; mkdir -p "$W"
R=$W/repo; mkdir -p "$R"; cd "$R"; git init -q; git config user.email rt@x; git config user.name rt
cat > hook.c <<'C'
#include "hookapi.h"
int64_t hook(uint32_t r) { _g(1,1); return accept(0, 0, 10); }   /* reviewed: returns 10 */
C
git add -A && git commit -qm genuine; C=$(git rev-parse HEAD); T=$(git rev-parse HEAD^{tree})
EB=$(sed 's/accept(0, 0, 10)/accept(0, 0, 1000000)/' hook.c | git hash-object -w --stdin)
T2=$(printf '100644 blob %s\thook.c\n' "$EB" | git mktree)
git replace "$T" "$T2"
echo "genuine commit $C tree $T; replacement tree $T2 (refs/replace/$T)"
echo "commit object unchanged: $(git cat-file commit $C | head -1)  (== $(GIT_NO_REPLACE_OBJECTS=1 git cat-file commit $C | head -1))"
TC="--toolchain hookc-llvm22 --platform linux/arm64"
"$HR/hookc" build --git "$R" --rev "$C" $TC --no-wce --out "$W/evil" >"$W/evil.json" 2>"$W/evil.log"; echo "hookc build exit=$?"
python3 -c "import json;d=json.load(open('$W/evil/0.hook.metadata.json'));print('sidecar HookHash',d['HookHash'],'vcs',d['source']['vcs'])"
"$HR/hookc" reproduce --metadata "$W/evil/0.hook.metadata.json" --src "$R" --platform linux/arm64 --no-wce 2>"$W/r-src.log"; echo "reproduce --src <repo> exit=$?"
"$HR/hookc" reproduce --metadata "$W/evil/0.hook.metadata.json" --git "$R" --platform linux/arm64 --no-wce 2>"$W/r-git.log"; echo "reproduce --git <repo> exit=$?"
git clone -q "$R" "$W/clean"
"$HR/hookc" reproduce --metadata "$W/evil/0.hook.metadata.json" --git "$W/clean" --platform linux/arm64 --no-wce 2>"$W/r-clean.log"; echo "reproduce --git <clean clone of same commit> exit=$?"
GIT_NO_REPLACE_OBJECTS=1 "$HR/hookc" reproduce --metadata "$W/evil/0.hook.metadata.json" --git "$R" --platform linux/arm64 --no-wce 2>"$W/r-norepl.log"; echo "reproduce with GIT_NO_REPLACE_OBJECTS=1 exit=$?"
# a MIRROR clone (refs/*:refs/*) of the author's repo carries refs/replace/* along
git clone -q --mirror "$R" "$W/mirror.git"; echo "mirror has: $(git -C "$W/mirror.git" for-each-ref refs/replace --format='%(refname)')"
"$HR/hookc" reproduce --metadata "$W/evil/0.hook.metadata.json" --git "$W/mirror.git" --platform linux/arm64 --no-wce 2>"$W/r-mirror.log"; echo "reproduce --git <git clone --mirror> exit=$?"

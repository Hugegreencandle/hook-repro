#!/bin/sh
# FP5: export_git writes git blobs onto the host FS. On macOS (case-insensitive APFS, the documented host)
# a commit holding both Cfg.h and cfg.h collapses to ONE file named Cfg.h with cfg.h's CONTENT.
# `hookc build --git` and `hookc reproduce --git` then say REPRODUCED for bytes compiled from content that
# is NOT what commit X's Cfg.h contains (what GitHub / a Linux checkout / a reviewer reads).
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=$RT/../rt-hookc; W=$RT/work-fp5; rm -rf "$W"; mkdir -p "$W"
R=$W/repo; mkdir -p "$R"; cd "$R"; git init -q; git config user.email rt@x; git config user.name rt; git config core.ignorecase false
printf '#include "hookapi.h"\n#include "Cfg.h"\nint64_t hook(uint32_t r) { _g(1,1); return accept(0, 0, LIMIT); }\n' > hook.c
# write the two colliding blobs straight into the index (they cannot coexist in a macOS work tree)
B=$(printf '#define LIMIT 10\n' | git hash-object -w --stdin)       # Cfg.h: reviewed
E=$(printf '#define LIMIT 1000000\n' | git hash-object -w --stdin)  # cfg.h: never included on Linux
git add hook.c
git update-index --add --cacheinfo 100644,$B,Cfg.h --cacheinfo 100644,$E,cfg.h
git commit -qm collide; X=$(git rev-parse HEAD); echo "commit $X tree:"; git ls-tree $X
# what a case-sensitive (Linux) export contains:
docker run --rm -v "$R/.git:/g:ro" --network none alpine/git@sha256:$(docker image inspect alpine/git --format '{{index .RepoDigests 0}}' 2>/dev/null | cut -d: -f2) \
  --git-dir=/g show $X:Cfg.h 2>/dev/null || git show $X:Cfg.h | sed 's/^/  git show X:Cfg.h => /'
TC="--toolchain hookc-llvm22 --platform linux/arm64"
"$HR/hookc" build --git "$R" --rev $X $TC --out "$W/mac" >/dev/null 2>"$W/mac.log"; echo "macOS hookc build --git exit=$?"
ls "$W/mac"; python3 -c "import json;d=json.load(open('$W/mac/0.hook.metadata.json'));print('mac HookHash',d['HookHash'],'vcs.commit',d['source']['vcs']['commit'],'file_count',d['source']['file_count'])"
"$HR/hookc" reproduce --metadata "$W/mac/0.hook.metadata.json" --git "$R" --platform linux/arm64 >"$W/repro.out" 2>&1; echo "macOS reproduce --git exit=$?"; head -2 "$W/repro.out"
# reference: the bytes a case-sensitive checkout compiles (Cfg.h = LIMIT 10, cfg.h unused)
R2=$W/ref; mkdir -p "$R2"; cd "$R2"; git init -q; git config user.email rt@x; git config user.name rt
git -C "$R" show $X:hook.c > hook.c; git -C "$R" show $X:Cfg.h > Cfg.h; git add -A; git commit -qm ref
"$HR/hookc" build --git "$R2" $TC --out "$W/ref-out" >/dev/null 2>"$W/ref.log"; echo "reference build exit=$?"
python3 -c "import json;print('reference (Linux-equivalent) HookHash',json.load(open('$W/ref-out/0.hook.metadata.json'))['HookHash'])"

#!/bin/sh
# N1b: no replace refs; the loose TREE object file for genuine tree T is overwritten with a different
# tree's content (object id no longer matches). Does export_tree notice? (blobs are re-hashed; trees
# and commits are not.)
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=$RT/../rt2-hookc; W=$RT/work-n1b; rm -rf "$W"; mkdir -p "$W"
R=$W/repo; mkdir -p "$R"; cd "$R"; git init -q; git config user.email rt@x; git config user.name rt
printf 'int x = 1; /* GENUINE */\n' > hook.h; git add hook.h; git commit -qm genuine
C=$(git rev-parse HEAD); T=$(git rev-parse HEAD^{tree})
EB=$(printf 'int x = 666; /* EVIL */\n' | git hash-object -w --stdin)
T2=$(printf '100644 blob %s\thook.h\n' "$EB" | git mktree)
f=.git/objects/$(echo $T | cut -c1-2)/$(echo $T | cut -c3-); f2=.git/objects/$(echo $T2 | cut -c1-2)/$(echo $T2 | cut -c3-)
chmod u+w "$f"; cp "$f2" "$f"
echo "git ls-tree $T => $(git ls-tree $T 2>&1)"
cd "$HR" && python3 - "$R" "$C" "$W/out" <<'PY'
import sys; from hook_repro import hookc
try:
    info = hookc.export_tree(*sys.argv[1:4], ) if False else hookc.export_tree(sys.argv[1], sys.argv[2], "", sys.argv[3])
    print("export vcs tree:", info["vcs"]["tree"], "hook.h:", open(sys.argv[3] + "/hook.h").read().strip())
except Exception as e:
    print("export refused:", type(e).__name__, str(e)[:200])
PY

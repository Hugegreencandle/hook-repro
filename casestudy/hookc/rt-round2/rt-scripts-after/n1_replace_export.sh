#!/bin/sh
# N1 (export level): `git replace` of a TREE object. The commit and tree ids the sidecar would
# record are the genuine ones, but export_tree ls-trees the REPLACEMENT tree's files.
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=$RT/../rt2-hookc; W=$RT/work-n1x; rm -rf "$W"; mkdir -p "$W"
cd "$W"; git init -q repo; cd repo
git config user.email a@b; git config user.name a
printf 'int x = 1; /* GENUINE */\n' > hook.h; git add hook.h; git commit -qm genuine
C=$(git rev-parse HEAD); T=$(git rev-parse HEAD^{tree})
EVIL_BLOB=$(printf 'int x = 666; /* EVIL */\n' | git hash-object -w --stdin)
T2=$(printf '100644 blob %s\thook.h\n' $EVIL_BLOB | git mktree)
git replace $T $T2
echo "commit $C tree $T (replacement $T2)"
echo "git verify: cat-file -p C:hook.h => $(git cat-file -p $C:hook.h)"
echo "GIT_NO_REPLACE_OBJECTS=1        => $(GIT_NO_REPLACE_OBJECTS=1 git cat-file -p $C:hook.h)"
cd "$HR" && python3 - "$W/repo" "$C" "$W/out" <<'PY'
import sys; from hook_repro import hookc
repo, c, out = sys.argv[1:]
info = hookc.export_tree(repo, c, "", out)
print("export vcs:", info["vcs"])
print("exported hook.h:", open(out + "/hook.h").read().strip())
PY

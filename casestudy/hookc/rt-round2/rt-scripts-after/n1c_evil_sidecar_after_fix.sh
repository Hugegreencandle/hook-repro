#!/bin/sh
# N1c (fix check, real docker): the sidecar ec8eaeb's `hookc build --git <replaced repo>` wrote
# (vcs = GENUINE commit C / tree T, bytes + tree_sha256 of the REPLACEMENT content) can no longer
# be made by the fixed build, so it is reconstructed: build the evil content as its own repo, then
# point source.vcs at C/T (exactly what ec8eaeb recorded). Every route the red-team used must end
# MISMATCH (2) or UNVERIFIED (3): --src/--git of the replacing repo, a --mirror clone, GIT_DIR and
# GIT_REPLACE_REF_BASE from the caller's environment.
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=$RT/../rt2-hookc; W=$RT/work-n1c; rm -rf "$W"; mkdir -p "$W"
R=$W/repo; mkdir -p "$R"; cd "$R"; git init -q; git config user.email rt@x; git config user.name rt
cat > hook.c <<'C'
#include "hookapi.h"
int64_t hook(uint32_t r) { _g(1,1); return accept(0, 0, 10); }   /* reviewed: returns 10 */
C
git add -A && git commit -qm genuine; C=$(git rev-parse HEAD); T=$(git rev-parse HEAD^{tree})
sed 's/accept(0, 0, 10)/accept(0, 0, 1000000)/' hook.c > "$W/evil.c"
EB=$(git hash-object -w "$W/evil.c"); T2=$(printf '100644 blob %s\thook.c\n' "$EB" | git mktree); git replace "$T" "$T2"
E=$W/evilrepo; mkdir -p "$E"; cd "$E"; git init -q; git config user.email rt@x; git config user.name rt; cp "$W/evil.c" hook.c; git add -A; git commit -qm e
TC="--toolchain hookc-llvm22 --platform linux/arm64"
"$HR/hookc" build --git "$E" $TC --no-wce --out "$W/evil" >/dev/null 2>"$W/evil.log"; echo "evil-content build exit=$?"
python3 - "$W/evil/0.hook.metadata.json" "$C" "$T" "$W/evil-sidecar.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["source"]["vcs"].update(commit=sys.argv[2], tree=sys.argv[3])
open(sys.argv[4], "w").write(json.dumps(d, indent=2, ensure_ascii=False) + "\n")
print("reconstructed ec8eaeb sidecar: HookHash", d["HookHash"], "vcs", sys.argv[2][:12], sys.argv[3][:12])
PY
M="$W/evil-sidecar.json"
"$HR/hookc" reproduce --metadata "$M" --src "$R" --platform linux/arm64 --no-wce 2>/dev/null | head -2 > "$W/o1"; echo "reproduce --src <replacing repo>: $(head -1 "$W/o1")"
"$HR/hookc" reproduce --metadata "$M" --src "$R" --platform linux/arm64 --no-wce >/dev/null 2>&1; echo "  exit=$?"
"$HR/hookc" reproduce --metadata "$M" --git "$R" --platform linux/arm64 --no-wce >/dev/null 2>&1; echo "reproduce --git <replacing repo> exit=$?"
git clone -q --mirror "$R" "$W/mirror.git"; echo "mirror has: $(git -C "$W/mirror.git" for-each-ref refs/replace --format='%(refname)')"
"$HR/hookc" reproduce --metadata "$M" --git "$W/mirror.git" --platform linux/arm64 --no-wce >/dev/null 2>&1; echo "reproduce --git <mirror clone> exit=$?"
git clone -q "$R" "$W/clean"
GIT_DIR="$R/.git" "$HR/hookc" reproduce --metadata "$M" --git "$W/clean" --platform linux/arm64 --no-wce >/dev/null 2>&1; echo "GIT_DIR=<replacing repo> reproduce --git <clean clone> exit=$?"
git -C "$R" replace -d "$T" >/dev/null; git -C "$R" update-ref "refs/evil/$T" "$T2"
GIT_REPLACE_REF_BASE=refs/evil/ "$HR/hookc" reproduce --metadata "$M" --git "$R" --platform linux/arm64 --no-wce >/dev/null 2>&1; echo "GIT_REPLACE_REF_BASE=refs/evil/ reproduce exit=$?"

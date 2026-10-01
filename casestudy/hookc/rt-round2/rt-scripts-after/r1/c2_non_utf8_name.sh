#!/bin/sh
# C2: a git tree entry whose name is not valid UTF-8 crashes export_git with an uncaught UnicodeDecodeError
# (traceback, exit 1) instead of a fail-closed exit 3.
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=$RT/../rt-hookc; W=$RT/work-c2; rm -rf "$W"; mkdir -p "$W/repo"; cd "$W/repo"
git init -q; git config user.email rt@x; git config user.name rt
B=$(printf 'x\n' | git hash-object -w --stdin)
T=$(printf '100644 bad\377name\0' | cat - /dev/null > /dev/null; python3 -c "
import subprocess,sys
b=bytes.fromhex('$B'); body=b'100644 bad\xffname\0'+b
print(subprocess.run(['git','hash-object','-t','tree','--literally','-w','--stdin'],input=body,capture_output=True).stdout.decode().strip())")
C=$(git commit-tree $T -m bad)
"$HR/hookc" build --git "$W/repo" --rev $C --toolchain hookc-llvm22 --platform linux/arm64 --out "$W/o" > "$W/out" 2>&1; echo "exit=$?"; tail -1 "$W/out"

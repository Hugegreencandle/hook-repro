#!/bin/sh
# FN1: `hookc build <worktree>` hashes the checked-out bytes, `reproduce --git` hashes raw blobs. With
# core.autocrlf=true (default on Git for Windows) an honest, clean work tree yields metadata that
# `hookc reproduce --git` refuses forever (tree_sha256 mismatch), although git says the tree is identical.
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=$RT/../rt-hookc; W=$RT/work-fn1; rm -rf "$W"; mkdir -p "$W/up"
cd "$W/up"; git init -q; git config user.email rt@x; git config user.name rt
printf '#include "hookapi.h"\nint64_t hook(uint32_t r) { _g(1,1); return accept(0, 0, 0); }\n' > hook.c
git add -A; git commit -qm init
git clone -q -c core.autocrlf=true "$W/up" "$W/win"; echo "status: [$(git -C "$W/win" status --porcelain)]  crlf: $(grep -c $'\r' "$W/win/hook.c")"
TC="--toolchain hookc-llvm22 --platform linux/arm64"
"$HR/hookc" build "$W/win" $TC --out "$W/o" >/dev/null 2>"$W/b.log"; echo "build exit=$?"
"$HR/hookc" reproduce --metadata "$W/o/0.hook.metadata.json" --git "$W/up" --platform linux/arm64 >"$W/r.out" 2>&1; echo "reproduce --git exit=$? $(tail -1 "$W/r.out" | cut -c1-110)"

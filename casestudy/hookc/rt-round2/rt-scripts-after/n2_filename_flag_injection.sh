#!/bin/sh
# N2: a top-level FILE NAME becomes clang arguments. Every pipeline builds
# CLANG_CMD="... $SOURCES" from `find -name '*.c'` and runs it unquoted, so a committed file named
# '-DLIMIT=1000000 -Wno-x.c' injects -DLIMIT=1000000 (the file's content is never compiled).
# The sidecar says entry=null ("every top-level .c") and REPRODUCED holds; the reviewed hook.c
# reads LIMIT 10. Bytes == an explicit LIMIT=1000000 build.
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=$RT/../rt2-hookc; W=$RT/work-n2; rm -rf "$W"; mkdir -p "$W"
TC="--toolchain hookc-llvm22 --platform linux/arm64 --no-wce"
mk() { # dir limitdefault extra
  mkdir -p "$1"; cd "$1"; git init -q; git config user.email rt@x; git config user.name rt
  printf '#include "hookapi.h"\n#ifndef LIMIT\n#define LIMIT %s   /* reviewed value */\n#endif\nint64_t hook(uint32_t r) { _g(1,1); return accept(0, 0, LIMIT); }\n' "$2" > hook.c
  [ -n "${3:-}" ] && printf '/* release notes */\n' > "$3"
  git add -A; git commit -qm c; cd - >/dev/null
}
mk "$W/honest" 10
mk "$W/inject" 10 '-DLIMIT=1000000 -Wno-x.c'
mk "$W/explicit" 1000000
for v in honest inject explicit; do
  "$HR/hookc" build --git "$W/$v" $TC --out "$W/out-$v" >"$W/$v.json" 2>"$W/$v.log"; echo "$v build exit=$?"
  python3 -c "import json;d=json.load(open('$W/out-$v/0.hook.metadata.json'));print('  $v HookHash',d['HookHash'],'entry',d['source']['entry'],'file_count',d['source']['file_count']);print('  cmd:',d['builder']['commands'][0][-80:])"
done
echo "git ls-files (inject): $(git -C "$W/inject" ls-files | tr '\n' '|')"
"$HR/hookc" reproduce --metadata "$W/out-inject/0.hook.metadata.json" --git "$W/inject" --platform linux/arm64 --no-wce 2>/dev/null; echo "reproduce inject exit=$?"

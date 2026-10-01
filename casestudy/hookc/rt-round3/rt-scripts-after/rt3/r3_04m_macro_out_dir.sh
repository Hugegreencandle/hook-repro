#!/bin/sh
# R3-04 variant (RT3 fix session): the '..' pre-scan is only a belt, so the literal r3_04/04a
# sources are now refused before any container runs. This variant hides the operand in a macro
# (the pre-scan cannot see it) so the ENFORCEMENT is exercised with real docker + clang:
# (a) r3_04a: two builds into the same --out, then two reviewer reproduces into one --out;
# (b) r3_04: the out dir pre-populated with payload.h. Run against $HR (default ../rt3-hookc).
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=${HR:-$RT/../rt3-hookc}; W=$RT/work-r3-04m; rm -rf "$W"; mkdir -p "$W/repo"
cd "$W/repo" && git init -q && git config user.email rt@x && git config user.name rt
cat > hook.c <<'C'
#include <stdint.h>
extern int32_t _g(uint32_t id, uint32_t maxiter);
extern int64_t accept(uint32_t read_ptr, uint32_t read_len, int64_t error_code);
#define STR(x) #x
#define XSTR(x) STR(x)
#define OUTW ../../out/hook.wasm
#define OUTP ../../out/payload.h
#if __has_include(XSTR(OUTW))
#define V 2
#else
#define V 1
#endif
#if __has_include(XSTR(OUTP))
#include XSTR(OUTP)
#else
#define PAYLOAD 0
#endif
int64_t hook(uint32_t reserved) { _g(1, 1); return accept(0, 0, V * 1000 + PAYLOAD); }
C
git add . && git commit -qm h && cd "$RT"
hh() { python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['HookHash'])" "$1" 2>/dev/null || echo NONE; }
B() { "$HR/hookc" build --git "$W/repo" --toolchain hookc-llvm22 --platform linux/arm64 --no-wce --out "$1" > "$W/b.out" 2>&1; echo $?; }
echo "fresh build exit=$(B "$W/fresh") HookHash $(hh "$W/fresh/0.hook.metadata.json")"
echo "(a) build 1 into o exit=$(B "$W/o") HookHash $(hh "$W/o/0.hook.metadata.json")"
echo "(a) build 2 into same o exit=$(B "$W/o") HookHash $(hh "$W/o/0.hook.metadata.json")"
M="$W/o/0.hook.metadata.json"
for n in 1 2; do
  "$HR/hookc" reproduce --metadata "$M" --git "$W/repo" --no-wce --out "$W/rev" > "$W/r$n.out" 2>&1; rc=$?
  echo "(a) reviewer run $n --out rev: exit=$rc $(grep -m1 VERDICT "$W/r$n.out")"
done
for b in build1 build2; do mkdir -p "$W/p/builds/linux-arm64/$b"; echo '#define PAYLOAD 0x31337' > "$W/p/builds/linux-arm64/$b/payload.h"; done
echo "(b) build into pre-populated out exit=$(B "$W/p") HookHash $(hh "$W/p/0.hook.metadata.json")"

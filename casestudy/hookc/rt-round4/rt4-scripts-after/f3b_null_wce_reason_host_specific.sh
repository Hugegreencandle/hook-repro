#!/bin/sh
# F3b: when the builder's WCE tool cannot run, the sidecar is still written (exit 0) with WCE null and a
# builder.wce.reason that embeds host-specific text (a local docker image ID). README: "No host paths,
# times or image IDs, so it is platform-independent". The same source + toolchain on a host whose WCE tool
# works regenerates a different sidecar -> MISMATCH.
set -u
HR=<repo>; S=$(cd "$(dirname "$0")" && pwd); W=$S/work-f3b; rm -rf "$W"; mkdir -p "$W"
C=$W/cache; mkdir -p "$C/images"; cp -R "$HOME/.cache/hook-repro/images/hookc-llvm22" "$C/images/"
HOOK_REPRO_CACHE=$C "$HR/hookc" build --git "$S/work-f2/repo" --toolchain hookc-llvm22 --platform linux/arm64 --out "$W/o" >/dev/null 2>"$W/b.err"; echo "build (WCE tool unavailable) exit=$?"
python3 -c "import json;d=json.load(open('$W/o/0.hook.metadata.json'));print('WCE',d['WCE']);print('reason',d['builder']['wce']['reason'])"
"$HR/hookc" reproduce --metadata "$W/o/0.hook.metadata.json" --git "$S/work-f2/repo" >"$W/r.out" 2>&1; echo "reproduce on a host whose WCE tool works exit=$?"; head -2 "$W/r.out"

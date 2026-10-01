#!/bin/sh
# F3: an HONEST sidecar (built with WCE) gets MISMATCH (exit 2), not UNVERIFIED, when the verifier's WCE tool
# does not run: (a) `hookc reproduce --no-wce`; (b) the hookc-wce image is unavailable on the verifier's host
# (simulated: a cache dir that has the hookc-llvm22 image record but not the hookc-wce one, so ensure_image
# refuses the tag) for both `hookc reproduce` and `hook-repro verify`. A tool failure is reported as a
# content mismatch. Uses the F2 honest build + a clean clone.
set -u
HR=<repo>; S=$(cd "$(dirname "$0")" && pwd); W=$S/work-f3; rm -rf "$W"; mkdir -p "$W"
M=$S/work-f2/o/0.hook.metadata.json; git clone -q "$S/work-f2/repo" "$W/clone"
python3 -c "import json;print('sidecar WCE', json.load(open('$M'))['WCE'])"
"$HR/hookc" reproduce --metadata "$M" --git "$W/clone" >"$W/a.out" 2>&1; echo "(0) control reproduce exit=$?"; head -1 "$W/a.out"
"$HR/hookc" reproduce --metadata "$M" --git "$W/clone" --no-wce >"$W/b.out" 2>&1; echo "(a) reproduce --no-wce exit=$?"; head -2 "$W/b.out"
C=$W/cache; mkdir -p "$C/images"; cp -R "$HOME/.cache/hook-repro/images/hookc-llvm22" "$C/images/"
HOOK_REPRO_CACHE=$C "$HR/hookc" reproduce --metadata "$M" --git "$W/clone" >"$W/c.out" 2>&1; echo "(b) reproduce, WCE tool unavailable exit=$?"; head -2 "$W/c.out" | cut -c1-300
HOOK_REPRO_CACHE=$C python3 "$S/stub_verify.py" "$HR" "$S/work-f2/o/0.hook.wasm" "$M" --git "$W/clone" --out "$W/v" 2>/dev/null | grep -E "VERDICT|reason|exit=" | cut -c1-300
python3 -c "import json;r=json.load(open('$W/v/verify-report.json'));print('verify metadata_diff', r.get('metadata_diff'))"

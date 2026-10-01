#!/bin/sh
# R3-08: malformed inputs that end in a Python traceback (exit 1) instead of UNVERIFIED (exit 3).
# None prints REPRODUCED. Uses the R3-01 sidecar/repo (run r3_01 first).
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=$RT/../rt3-hookc; W=$RT/work-r3-08; rm -rf "$W"; mkdir -p "$W"
M=$RT/work-r3-01/o/0.hook.metadata.json; R=$RT/work-r3-01/repo
"$HR/hookc" reproduce --metadata "$M" --git "$R" --wasm /nonexistent.wasm > "$W/a.out" 2>&1; echo "(a) --wasm missing file: exit=$? $(tail -1 "$W/a.out" | cut -c1-120)"
python3 - "$M" "$W/b.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["builder"]["platforms"]["linux/arm64"] = "not-an-object"
open(sys.argv[2], "w").write(json.dumps(d, indent=2) + "\n")
PY
"$HR/hookc" reproduce --metadata "$W/b.json" --git "$R" > "$W/b.out" 2>&1; echo "(b) builder.platforms twin not an object: exit=$? $(tail -1 "$W/b.out" | cut -c1-120)"
python3 - "$M" "$W/c.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["human"] = "x"
open(sys.argv[2], "w").write(json.dumps(d, indent=2) + "\n")
PY
"$HR/hookc" reproduce --metadata "$W/c.json" --git "$R" --no-wce > "$W/c.out" 2>&1; echo "(c) human not an object: exit=$? $(grep -m1 VERDICT "$W/c.out") $(tail -1 "$W/c.out" | cut -c1-120)"

#!/bin/sh
# N6 (OVERCLAIM, LOW): `hookc build --platform linux/arm64` builds ONE twin, yet the sidecar's
# builder.platforms lists every twin, so it is indistinguishable from a sidecar whose twins were
# all built and cross-compared. Uses the N2 honest build (run n2_filename_flag_injection.sh first).
RT=$(cd "$(dirname "$0")" && pwd); W=$RT/work-n2
python3 - "$W" <<'PY'
import json, sys, os
w = sys.argv[1]
s = json.load(open(w + "/honest.json")); m = json.load(open(w + "/out-honest/0.hook.metadata.json"))
print("twins actually built (build summary):", sorted(s["platforms"]))
print("builds dirs on disk:", sorted(os.listdir(w + "/out-honest/builds")))
print("sidecar builder.platforms:          ", sorted(m["builder"]["platforms"]))
print("any sidecar field recording which twins were built:", any(k in m["builder"] for k in ("built_platforms", "cross_checked")))
PY

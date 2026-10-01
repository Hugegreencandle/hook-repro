#!/bin/sh
# FP6: builder.preset is a free label. Build metadata always records the fully-resolved params, which override
# every key of any preset, so a sidecar can say preset "builder-2025" (Hooks Builder 2025 pipeline) while the
# bytes come from the "classic" params, and `hookc reproduce` still says REPRODUCED, "metadata identical".
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=$RT/../rt-hookc; W=$RT/work-fp6; rm -rf "$W"; mkdir -p "$W"
CR=$HOME/.cache/hook-repro/src/cron-claimreward-xahau
python3 - "$HR/casestudy/hookc/claimreward/0.hook.metadata.json" "$W/m.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d["builder"]["preset"] = "builder-2025"
open(sys.argv[2], "w").write(json.dumps(d, indent=2, ensure_ascii=False) + "\n")
PY
echo "preset=$(python3 -c "import json;d=json.load(open('$W/m.json'))['builder'];print(d['preset'],d['params'])")"
"$HR/hookc" reproduce --metadata "$W/m.json" --git "$CR" 2>"$W/log"; echo "exit=$?"

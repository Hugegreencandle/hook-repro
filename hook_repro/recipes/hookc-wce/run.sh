#!/bin/sh
# hookc-wce runner: /src/hook.wasm (ro) -> /out/wce.json. --network none, read-only.
set -eu
export TZ=UTC LC_ALL=C
rc=0; /tc/hookc-wce /src/hook.wasm > /out/wce.json 2> /out/wce.log || rc=$?
echo "$rc" > /out/wce.rc

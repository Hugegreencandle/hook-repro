# rshooks-compat checks: (1) byte round-trip of real rshooks-build 0.2.3 sidecars through hookc.dumps;
# (2) schema differences vs rshooks-build 0.2.3 entry_sidecar.rs (chain is a required object there).
import json, sys, glob, os
sys.path.insert(0, '../rt-hookc')
from hook_repro import hookc as HC
fx = glob.glob('../rt-hookc/tests/fixtures/rshooks/*.metadata.json') + glob.glob('../rt-hookc/casestudy/rshooks/**/*.metadata.json', recursive=True)
for p in fx:
    raw = open(p).read(); print("roundtrip", HC.dumps(json.loads(raw)) == raw, os.path.relpath(p, '..'))
d = json.load(open('../rt-hookc/casestudy/hookc/claimreward/0.hook.metadata.json'))
rs = json.load(open('../rt-hookc/tests/fixtures/rshooks/recorded_firewall_0.main.metadata.json'))
print("hookc chain:", d["chain"], "| rshooks chain type:", type(rs["chain"]).__name__, "(entry_sidecar.rs: `chain: ChainSummary`, not Option)")
print("rshooks builder keys:", list(rs["builder"])); print("hookc builder keys:  ", list(d["builder"]))
print("keys rshooks has that hookc builder lacks:", [k for k in rs["builder"] if k not in d["builder"]])

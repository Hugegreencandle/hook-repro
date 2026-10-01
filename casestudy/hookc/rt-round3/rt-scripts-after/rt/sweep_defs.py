# Read-only: page ledger_data(type=hook_definition) on xahau.network at one validated ledger; save definitions.
import json, sys, time; sys.path.insert(0, '.')
from rpc import rpc
U = "https://xahau.network"; out = []; marker = None; li = None; calls = 0
while calls < 600:
    p = {"type": "hook_definition", "limit": 2048}
    p.update({"ledger_index": li, "marker": marker} if marker else {"ledger_index": "validated"})
    r = rpc(U, "ledger_data", p); calls += 1
    li = r["ledger_index"]; out += r.get("state", [])
    marker = r.get("marker")
    if calls % 25 == 0: print(calls, len(out), file=sys.stderr)
    if not marker: break
json.dump({"ledger_index": li, "complete": marker is None, "calls": calls, "defs": out}, open("defs.json", "w"))
print("ledger", li, "defs", len(out), "complete", marker is None, "calls", calls)

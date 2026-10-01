# Run hookc's WCE tool (xahaud validateGuards @bb244ef, recipe hookc-wce) on every mainnet CreateCode and
# compare with the HookDefinition Fee / HookCallbackFee that SetHook stored.
import json, sys
sys.path.insert(0, '../rt-hookc')
from hook_repro import hookc as HC
from hook_repro.hashing import sha512half
D = json.load(open("defs.json")); rows = []
for i, d in enumerate(D["defs"]):
    code = bytes.fromhex(d["CreateCode"])
    try:
        wce, why = HC.run_wce(code, log=lambda *_: None)
    except HC.HookcError as e:
        wce, why = None, "REJECTED: " + str(e)[:200]
    fee = int(d.get("Fee", "0")); cb = int(d.get("HookCallbackFee", "0"))
    row = {"HookHash": d["HookHash"], "size": len(code), "hash_ok": sha512half(code) == d["HookHash"],
           "Fee": fee, "HookCallbackFee": cb, "has_cbfee": "HookCallbackFee" in d,
           "wce": wce, "why": why, "HookSetTxnID": d.get("HookSetTxnID"),
           "match": (wce is not None and wce["hook"] == fee and wce["cbak"] == cb)}
    rows.append(row)
    print(i, d["HookHash"][:16], len(code), fee, cb, wce, "MATCH" if row["match"] else "DIFF", (why or "")[:80], flush=True)
json.dump({"ledger_index": D["ledger_index"], "rows": rows}, open("wce_sweep.json", "w"), indent=1)
n = len(rows); m = sum(r["match"] for r in rows)
print("TOTAL", n, "match", m, "diff", n - m)

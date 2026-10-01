# N4: verify's "enforced" HookDefinition.HookOn row. xahaud SetHook.cpp @bb244ef:1845-1848 stores the
# CREATING SetHook's HookOn in the definition (like HookCanEmit, which hook-repro calls informational),
# and :1630-1640 stores a per-installation HookOn override on the account's Hook entry. So
#  (a) honest bytes + honest sidecar, first installer chose another HookOn  -> MISMATCH (exit 2);
#  (b) a HookOnV2 definition (HookOnIncoming/Outgoing, no HookOn), sidecar HookOn declared
#      -> row n/a, verdict REPRODUCED and the reason still says "...HookOn agree".
# Offline: fake transport (two nodes, same validated ledger) + fake builder + accepting sidecar check.
import sys; sys.path.insert(0, '../rt2-hookc')
from hook_repro.verify import verify, EXIT
from hook_repro.hashing import sha512half
code = open('../rt2-hookc/tests/fixtures/tiny.wasm', 'rb').read(); H = sha512half(code)
DECL = "F" * 63 + "E"
def transport_with(defn):
    def t(url, payload):
        if payload["method"] == "server_info":
            return {"result": {"status": "success", "info": {"pubkey_node": "n9" + url[-6:], "network_id": 21337}}}
        node = {"LedgerEntryType": "HookDefinition", "HookHash": H, "CreateCode": code.hex().upper(),
                "Fee": "20"} | defn
        return {"result": {"status": "success", "validated": True, "ledger_index": 100, "ledger_hash": "AB" * 32, "node": node}}
    return t
builder = lambda src, r, p, pr, o: ({"recipe": {"digest": "d"}, "image": {"image_id": "i"}, "source": {"tree_sha256": "t"}, "params": {}}, code)
meta = {"hookhash": H, "doc": {"WCE": {"hook": 20, "cbak": 0}, "HookOn": DECL, "HookCanEmit": None}}
for label, defn in [("(a) definition HookOn = another installer choice", {"HookOn": "0" * 64}),
                    ("(b) HookOnV2 definition, no HookOn field", {"HookOnIncoming": "0" * 64, "HookOnOutgoing": "F" * 64})]:
    rep = verify(H, ".", "hookc-llvm22", transport=transport_with(defn), builder=builder, metadata=meta,
                 sidecar=lambda w, m, b=None: (True, None, []))
    print(label, "->", rep["verdict"], "exit", EXIT[rep["verdict"]])
    print("   reason:", rep["reason"])
    print("   rows:", [(r["definition"], r["match"], r["enforced"]) for r in rep["definition_check"]["fields"]])

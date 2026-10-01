# L1: fetch.py's "two operators" test is len({server_info.pubkey_node}) >= 2. pubkey_node is self-reported and
# unauthenticated; one backend (or one proxy in front of one node) answering two hostnames with two different
# pubkey_node strings passes as two operators. Nothing ties the answer to a validated ledger hash either.
import sys; sys.path.insert(0, '../rt-hookc')
from hook_repro.fetch import fetch_createcode
from hook_repro.hashing import sha512half
code = open('../rt-hookc/tests/fixtures/tiny.wasm', 'rb').read(); H = sha512half(code)
def one_backend(url, payload):          # the SAME fabricated state for both hostnames
    if payload["method"] == "server_info":
        return {"result": {"status": "success", "info": {"pubkey_node": "n9FAKE_" + url[-5:], "network_id": 21337}}}
    return {"result": {"status": "success", "validated": True, "ledger_index": 1, "node": {
        "LedgerEntryType": "HookDefinition", "HookHash": H, "CreateCode": code.hex().upper()}}}
f = fetch_createcode(H, "xahau-mainnet", transport=one_backend)
print("ok", f["ok"], "distinct_operators", f.get("distinct_operators"), "(HookHash", H[:16], "is not on mainnet)")

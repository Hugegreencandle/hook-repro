"""Run `hook-repro verify --metadata <hookc sidecar>` (cli.main, unmodified code) against a SIMULATED
two-operator chain read: http_transport is replaced by a stub that serves `wasm` as the validated
HookDefinition CreateCode from two distinct pubkey_node values. Only the chain read is simulated.
usage: stub_verify.py HR WASM METADATA (--git R | --src D) [extra cli args...]"""
import json, sys, os
HR, WASM, META = sys.argv[1:4]
sys.path.insert(0, HR)
from hook_repro import fetch, cli
from hook_repro.hashing import sha512half
code = open(WASM, "rb").read(); H = sha512half(code)
meta = json.load(open(META)); wce = meta.get("WCE") or {}
def stub(url, payload, timeout=20):
    if payload["method"] == "server_info":
        return {"result": {"status": "success", "info": {"pubkey_node": "n9STUB" + url[-8:], "network_id": 21337, "build_version": "stub"}}}
    node = {"LedgerEntryType": "HookDefinition", "HookHash": H, "CreateCode": code.hex().upper()}
    if wce.get("hook") is not None: node["Fee"] = str(wce["hook"])
    if wce.get("cbak"): node["HookCallbackFee"] = str(wce["cbak"])
    return {"result": {"status": "success", "validated": True, "ledger_index": 100, "ledger_hash": "AB" * 32, "node": node}}
fetch.http_transport = stub
rc = cli.main(["verify", "--hookhash", H, "--metadata", META] + sys.argv[4:])
print("verify exit=%d (chain read SIMULATED)" % rc)

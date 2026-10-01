"""Read-only fetch of a HookDefinition's CreateCode from two operators.

Fail-closed: any read failure, unvalidated ledger, operator disagreement, hash mismatch,
wrong network, both endpoints being the same node, or the endpoints not returning the SAME
validated ledger hash at ONE ledger index => ok=False with the reason.
Only JSON-RPC reads are issued (server_info, ledger_entry). No keys, no submits.

Trust model (what a pass does and does not prove): every endpoint is trusted to answer
from the network's validated ledger. "Two operators" means two endpoints that report two
different `pubkey_node` values; that key is self-reported and unauthenticated, so it is a
fingerprint of which node answered, not proof of independence (one proxy can present two
keys). The same-ledger-hash rule makes all reads describe one ledger, which an honest
second operator confirms; a single dishonest backend can still answer consistently for
both hostnames. No SHAMap proof of the HookDefinition is checked.
"""
import json
import re
import urllib.request

from .hashing import sha512half

NETWORKS = {
    "xahau-mainnet": {"network_id": 21337,
                      "endpoints": ["https://xahau.network", "https://cluster.cbotlabs.xyz"]},
    # Measured 2026-09-28: both testnet hostnames answer from ONE node (same pubkey_node),
    # so testnet reads are single-operator and are refused unless allow_single_operator.
    "xahau-testnet": {"network_id": 21338,
                      "endpoints": ["https://xahau-test.net", "https://hooks-testnet-v3.xrpl-labs.com"]},
}
ALIASES = {"mainnet": "xahau-mainnet", "testnet": "xahau-testnet"}
USER_AGENT = "hook-repro/0.1 (read-only)"
HEX64 = re.compile(r"^[0-9A-Fa-f]{64}$")


class RpcError(RuntimeError):
    pass


def http_transport(url, payload, timeout=20):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"content-type": "application/json",
                                          "user-agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except Exception as e:  # network, HTTP, JSON: all are read failures
        raise RpcError("%s: %s: %s" % (url, type(e).__name__, e))


def _result(resp, url, method):
    if not isinstance(resp, dict) or not isinstance(resp.get("result"), dict):
        raise RpcError("%s %s: malformed response" % (url, method))
    r = resp["result"]
    if r.get("status") != "success" or "error" in r:
        raise RpcError("%s %s: %s" % (url, method, r.get("error") or r.get("status")))
    return r


def read_endpoint(url, hookhash, transport, ledger_index="validated"):
    info = _result(transport(url, {"method": "server_info", "params": [{}]}), url, "server_info")
    info = info.get("info") or {}
    node_key = info.get("pubkey_node")
    if not node_key:
        raise RpcError("%s server_info: no pubkey_node" % url)
    le = _result(transport(url, {"method": "ledger_entry", "params": [
        {"hook_definition": hookhash, "ledger_index": ledger_index}]}), url, "ledger_entry")
    if le.get("validated") is not True:
        raise RpcError("%s ledger_entry: ledger not validated" % url)
    if type(le.get("ledger_index")) is not int or (ledger_index != "validated" and le["ledger_index"] != ledger_index):
        raise RpcError("%s ledger_entry: ledger_index %r is not the one requested (%r)" % (url, le.get("ledger_index"), ledger_index))
    if not HEX64.match(str(le.get("ledger_hash", ""))):
        raise RpcError("%s ledger_entry: no validated ledger_hash" % url)
    node = le.get("node") or {}
    if node.get("LedgerEntryType") != "HookDefinition":
        raise RpcError("%s ledger_entry: not a HookDefinition" % url)
    if str(node.get("HookHash", "")).upper() != hookhash:
        raise RpcError("%s ledger_entry: HookHash field %r != requested" % (url, node.get("HookHash")))
    cc = node.get("CreateCode")
    if not cc:
        raise RpcError("%s ledger_entry: CreateCode missing" % url)
    try:
        code = bytes.fromhex(cc)
    except ValueError:
        raise RpcError("%s ledger_entry: CreateCode is not hex" % url)
    return {"url": url, "node_key": node_key, "network_id": info.get("network_id"),
            "build_version": info.get("build_version"), "ledger_index": le.get("ledger_index"),
            "ledger_hash": le.get("ledger_hash"), "code": code,
            "hook_set_txn": node.get("HookSetTxnID"),
            "definition": {k: v for k, v in node.items() if k != "CreateCode"}}


def fetch_createcode(hookhash, network="xahau-mainnet", transport=None, endpoints=None,
                     allow_single_operator=False):
    """Return dict with ok, reason, code (bytes|None), reads[]."""
    transport = transport or http_transport
    network = ALIASES.get(network, network)
    out = {"ok": False, "reason": None, "code": None, "reads": [], "errors": [],
           "network": network, "hookhash": hookhash}
    if not HEX64.match(hookhash or ""):
        out["reason"] = "hookhash is not 64 hex chars"
        return out
    hookhash = hookhash.upper()
    out["hookhash"] = hookhash
    if network not in NETWORKS:
        out["reason"] = "unknown network %r" % network
        return out
    net = NETWORKS[network]
    endpoints = list(endpoints or net["endpoints"])
    if len(endpoints) < 2:
        out["reason"] = "need at least two endpoints"
        return out
    for url in endpoints:
        try:
            out["reads"].append(read_endpoint(url, hookhash, transport))
        except RpcError as e:
            out["errors"].append(str(e))
    if out["errors"]:
        out["reason"] = "read failure: " + "; ".join(out["errors"])
        return out
    # all reads must describe ONE validated ledger: re-read the newer endpoints at the
    # oldest validated index any of them returned
    li = min(r["ledger_index"] for r in out["reads"])
    reread_errors = []
    for i, r in enumerate(out["reads"]):
        if r["ledger_index"] != li:
            try:
                out["reads"][i] = read_endpoint(r["url"], hookhash, transport, ledger_index=li)
            except RpcError as e:
                reread_errors.append(str(e))
    if reread_errors:
        out["errors"] += reread_errors
        out["reason"] = "read failure at common ledger %d: %s" % (li, "; ".join(reread_errors))
        return out
    hashes = {r["ledger_hash"].upper() for r in out["reads"] if r["ledger_index"] == li}
    if len(hashes) != 1 or any(r["ledger_index"] != li for r in out["reads"]):
        out["reason"] = "operators DISAGREE on validated ledger %d (%s)" % (li, ", ".join(
            "%s=%s@%s" % (r["url"], r["ledger_hash"][:16], r["ledger_index"]) for r in out["reads"]))
        return out
    out["ledger_index"], out["ledger_hash"] = li, hashes.pop()
    for r in out["reads"]:
        if r["network_id"] != net["network_id"]:
            out["reason"] = "%s reports network_id %r, expected %d" % (r["url"], r["network_id"], net["network_id"])
            return out
    codes = {r["code"] for r in out["reads"]}
    if len(codes) != 1:
        out["reason"] = "operators DISAGREE on CreateCode (%s)" % ", ".join(
            "%s=%s/%dB" % (r["url"], sha512half(r["code"])[:16], len(r["code"])) for r in out["reads"])
        return out
    code = codes.pop()
    got = sha512half(code)
    if got != hookhash:
        out["reason"] = "SHA512Half(CreateCode)=%s != requested HookHash" % got
        return out
    nodes = {r["node_key"] for r in out["reads"]}
    out["distinct_operators"] = len(nodes)
    if len(nodes) < 2 and not allow_single_operator:
        out["reason"] = ("all endpoints answered from ONE node (%s): not a two-operator read "
                         "(pass --allow-single-operator to accept, stated in the report)" % nodes.pop())
        return out
    out["ok"] = True
    out["code"] = code
    return out

"""bind-review: tie a review document's sha256 to one exact HookHash.

Emits an unsigned, signable manifest. Fail-closed on coverage: a review that never
states the full HookHash is not evidence about that binary (a known failure mode:
review evidence that described a different wasm), so no manifest is emitted without --force.
"""
import datetime
import json
import os
import re

from .hashing import sha256_file, sha256_hex

SCHEMA = "hook-repro/review-binding/v1"
HEX64 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")
TRUNC = re.compile(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{6,63})(?:…|\.\.\.)")


def coverage(text, hookhash):
    H = hookhash.upper()
    full = sorted({m.upper() for m in HEX64.findall(text)})
    if H in full:
        return "MENTIONS_HOOKHASH", [h for h in full if h != H]
    prefixes = {m.upper() for m in TRUNC.findall(text)}
    if any(H.startswith(p) for p in prefixes):
        return "MENTIONS_HOOKHASH_PREFIX_ONLY", full
    if full:
        return "MENTIONS_OTHER_HASHES_ONLY", full
    return "NOT_MENTIONED", []


def report_caveats(rep):
    """Plain statements of every qualification of a verify report's verdict (RT4 F4)."""
    out = []
    if rep.get("caveat"):
        out.append("verify report caveat: %s" % rep["caveat"])
    d = rep.get("distinct_operators")
    if type(d) is not int or d < 2:
        out.append("chain read from %s distinct operator(s), not two" % d)
    if rep.get("platforms_built_rechecked") is False:
        out.append("builder.platforms_built NOT re-checked (rebuilt only %s)" % "+".join(rep.get("platforms_rebuilt") or []))
    # RT5 P5: a null-WCE (--no-wce) sidecar leaves HookDefinition Fee/HookCallbackFee uncompared
    rows = (rep.get("definition_check") or {}).get("fields") or []
    uncompared = [str(r.get("definition")) for r in rows if r.get("enforced") and r.get("match") is None]
    wce = ((rep.get("metadata") or {}).get("doc") or {}).get("WCE")
    if uncompared or (isinstance(wce, dict) and wce.get("hook") is None):
        out.append("HookDefinition %s NOT compared: the sidecar's WCE is null (--no-wce)"
                   % "/".join(uncompared or ["Fee/HookCallbackFee"]))
    return out


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def bind_review(review_path, hookhash, network=None, verify_report=None, created_utc=None):
    """Return (manifest, ok). ok is False when coverage or the verify report fails."""
    if not re.match(r"^[0-9A-Fa-f]{64}$", hookhash or ""):
        raise ValueError("hookhash must be 64 hex chars")
    H = hookhash.upper()
    with open(review_path, "rb") as f:
        raw = f.read()
    cov, others = coverage(raw.decode("utf-8", "replace"), H)
    problems = []
    if cov != "MENTIONS_HOOKHASH":
        problems.append("review coverage is %s" % cov)
    vr, caveats = None, []
    if verify_report:
        with open(verify_report) as f:
            rep = json.load(f)
        vr = {"file": os.path.basename(verify_report), "sha256": sha256_file(verify_report),
              "verdict": rep.get("verdict"), "hookhash": rep.get("hookhash"),
              "recipe": rep.get("recipe"),
              "recipe_digest": (rep.get("builds") or [{}])[0].get("recipe_digest"),
              "source_tree_sha256": (rep.get("builds") or [{}])[0].get("source_tree_sha256"),
              # RT4 F4: what qualifies the verdict travels with it, so a binding over a single-operator
              # or --platform-restricted verify cannot pass for a two-operator, all-twins one
              "network": rep.get("network"),
              "distinct_operators": rep.get("distinct_operators"),
              "caveat": rep.get("caveat"),
              "platforms_built_rechecked": rep.get("platforms_built_rechecked"),
              "platforms_rebuilt": rep.get("platforms_rebuilt")}
        caveats = report_caveats(rep)
        if network is None:
            network = rep.get("network")
        elif rep.get("network") != network:
            problems.append("verify report is for network %s, not --network %s" % (rep.get("network"), network))
        if (rep.get("hookhash") or "").upper() != H:
            problems.append("verify report is for a different HookHash")
        if rep.get("verdict") != "REPRODUCED":
            problems.append("verify report verdict is %s" % rep.get("verdict"))
    m = {"schema": SCHEMA,
         "hookhash": H,
         "network": network,
         "review": {"file": os.path.basename(review_path), "sha256": sha256_hex(raw), "size": len(raw)},
         "coverage": cov,
         "other_hashes_mentioned": others[:32],
         "verify_report": vr,
         "caveats": caveats,
         "problems": problems,
         "created_utc": created_utc or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
         "signature": None,
         "signing_note": "sign sha256 of the canonical JSON (sorted keys, compact, UTF-8) of this object with 'signature' and 'canonical_sha256' removed"}
    body = {k: v for k, v in m.items() if k != "signature"}
    m["canonical_sha256"] = sha256_hex(canonical(body))
    return m, not problems

"""verify: on-ledger CreateCode (two operators) vs two clean rebuilds of stated source.

Verdicts (fail-closed; anything that is not a byte-identical match of a successful,
deterministic, two-operator-confirmed read is NOT a pass):
  REPRODUCED  both rebuilds identical to each other and to the on-ledger CreateCode
  MISMATCH    rebuild is deterministic but differs from on-ledger (section diff attached)
  UNVERIFIED  read failure, operator disagreement (CreateCode or validated ledger hash),
              hash mismatch, build failure, non-deterministic rebuild, or (--metadata) a
              sidecar whose HookHash is not the requested one

With a hookc sidecar (--metadata) the bytes must also justify the sidecar: the sidecar is
regenerated from the rebuild of the git export on EVERY rebuilt twin (each twin's own build
log) and must be byte-identical each time (else MISMATCH),
and the chain's HookDefinition Fee must equal the sidecar's WCE.hook and HookCallbackFee must
equal WCE.cbak (or be absent when WCE.cbak is 0: SetHook.cpp @bb244ef:1877 writes it only when
the callback count is > 0), else MISMATCH: SetHook derives both from the bytes
(computeExecutionFee of validateGuards). Only a null WCE leaves them uncompared. HookOn and HookCanEmit are compared and reported
but do not change the verdict: the definition stores the CREATING SetHook's values, which
the first installer chooses independently of the build (xahaud SetHook.cpp @bb244ef
:1845-1848 writes the creating transaction's HookOn into the new HookDefinition; :1630-1640
stores a per-installation HookOn override on the account's Hooks entry), and under
featureHookOnV2 a definition may carry HookOnIncoming/HookOnOutgoing and no HookOn at all.
The verdict reason names only the rows that were actually compared and equal.
"""
import datetime
import json
import os

from . import build as buildmod
from .fetch import fetch_createcode
from .hashing import sha256_hex, sha512half
from .wasm import diff as wasm_diff

REPORT_SCHEMA = "hook-repro/verify-report/v1"
EXIT = {"REPRODUCED": 0, "MISMATCH": 2, "UNVERIFIED": 3}


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def default_builder(src, recipe, params, preset, out_dir):
    return buildmod.build(src, recipe, params=params, preset=preset, out_dir=out_dir, log=lambda *_: None)


# SetHook derives Fee/HookCallbackFee from the bytes; HookOn/HookCanEmit are the first
# installer's choice (SetHook.cpp @bb244ef:1845-1848, per-install override :1630-1640).
ENFORCED_DEFINITION_FIELDS = ("Fee", "HookCallbackFee")
DEFINITION_FIELDS = ("Fee", "HookCallbackFee", "HookOn", "HookCanEmit")


def verify(hookhash, src, recipe="xhc-bin127", network="xahau-mainnet", params=None, preset=None,
           out_dir=None, transport=None, builder=None, allow_single_operator=False, endpoints=None, metadata=None,
           sidecar=None, twins=None, recheck_platforms_built=False, source_vcs=None):
    """sidecar: for a hookc sidecar, callable(wasm, manifest, built) -> (ok, reason, diff) that
    regenerates it from this rebuild (hookc.sidecar_check); required when metadata has one.
    twins: [(platform, recipe)] to rebuild twice EACH (default [(None, recipe)]); every twin's
    rebuild must be deterministic and equal the on-ledger CreateCode. recheck_platforms_built:
    the twins are exactly the sidecar's builder.platforms_built (no --platform restriction), so
    that claim is regenerated from what was rebuilt; otherwise it is reported NOT re-checked.
    The sidecar is regenerated from EVERY twin's rebuild (its own manifest and build log) and
    each must be byte-identical (RT5 P1). source_vcs: the git commit/tree the rebuild was
    exported from; recorded in the report before it is written (RT5 P2)."""
    builder = builder or default_builder
    twins = twins or [(None, recipe)]
    rep = {"schema": REPORT_SCHEMA, "generated_utc": _now(), "hookhash": (hookhash or "").upper(),
           "network": network, "source_dir": buildmod.portable_path(src), "recipe": recipe,
           "preset": preset, "params": params or {}, "verdict": "UNVERIFIED", "reason": None,
           "reads": [], "builds": [], "diff": None}
    if source_vcs is not None:
        rep["source_vcs"] = source_vcs
    if metadata:
        rep["metadata"] = {k: v for k, v in metadata.items() if k != "text"}
        rep["metadata_hookhash_matches"] = metadata["hookhash"] == rep["hookhash"]
        if not rep["metadata_hookhash_matches"]:
            rep["reason"] = "sidecar HookHash %s is not the requested HookHash %s" % (metadata["hookhash"], rep["hookhash"])
            return _finish(rep, out_dir, None)
    hookc_doc = bool(metadata and metadata.get("doc") is not None)
    if hookc_doc:
        rep["platforms_rebuilt"] = []  # filled only with twins actually rebuilt (twice, deterministic)
        rep["platforms_built_rechecked"] = False
    f = fetch_createcode(hookhash, network, transport=transport, endpoints=endpoints,
                         allow_single_operator=allow_single_operator)
    rep["network"] = f["network"]
    rep["reads"] = [{k: r[k] for k in ("url", "node_key", "network_id", "build_version",
                                       "ledger_index", "ledger_hash", "hook_set_txn")}
                    | {"size": len(r["code"]), "sha512half": sha512half(r["code"])}
                    for r in f["reads"]]
    rep["distinct_operators"] = f.get("distinct_operators")
    rep["ledger"] = {"ledger_index": f.get("ledger_index"), "ledger_hash": f.get("ledger_hash")}
    if allow_single_operator and f.get("distinct_operators") == 1:
        rep["caveat"] = "single-operator read accepted by --allow-single-operator"
    if not f["ok"]:
        rep["reason"] = f["reason"]
        return _finish(rep, out_dir, None)
    onledger = f["code"]
    per_twin = []
    for plat, rname in twins:
        rebuilt, manifests, builds = [], [], []
        on = " on %s" % plat if plat else ""
        for i in (1, 2):
            bdir = (os.path.join(out_dir, *([plat.replace("/", "-")] if plat else []), "build%d" % i)
                    if out_dir else None)
            try:
                manifest, wasm = builder(src, rname, params, preset, bdir)
            except Exception as e:  # any build failure is UNVERIFIED, never a pass
                rep["reason"] = "rebuild %d%s failed: %s: %s" % (i, on, type(e).__name__, str(e)[:1500])
                return _finish(rep, out_dir, onledger)
            rebuilt.append(wasm)
            manifests.append(manifest)
            b = {"n": i, "size": len(wasm), "sha512half": sha512half(wasm),
                 "sha256": sha256_hex(wasm),
                 "recipe_digest": manifest.get("recipe", {}).get("digest"),
                 "image_id": manifest.get("image", {}).get("image_id"),
                 "source_tree_sha256": manifest.get("source", {}).get("tree_sha256"),
                 "params": manifest.get("params")}
            if plat:
                b.update(platform=plat, recipe=rname)
            builds.append(b)
            rep["builds"].append(b)
        b1, b2 = rebuilt
        if b1 != b2:
            rep["reason"] = "rebuild%s is NOT deterministic (two clean builds differ)" % on
            rep["diff"] = wasm_diff(b1, b2, "build1", "build2")
            return _finish(rep, out_dir, onledger)
        t1, t2 = (b["source_tree_sha256"] for b in builds)
        if t1 != t2:
            rep["reason"] = "source tree changed between rebuilds%s" % on
            return _finish(rep, out_dir, onledger)
        i1, i2 = (b["image_id"] for b in builds)
        if i1 != i2:
            rep["reason"] = "rebuilds%s ran different images (%s, %s)" % (on, i1, i2)
            return _finish(rep, out_dir, onledger)
        per_twin.append((plat, b1, manifests[0]))
        if hookc_doc:
            rep["platforms_rebuilt"].append(plat)
    for plat, b1, _ in per_twin:
        if b1 != onledger:
            rep["verdict"] = "MISMATCH"
            rep["reason"] = "deterministic rebuild %s%s differs from on-ledger %s" % (
                sha512half(b1), " (%s twin)" % plat if plat else "", rep["hookhash"])
            rep["diff"] = wasm_diff(onledger, b1)
            return _finish(rep, out_dir, onledger)
    rechecked = bool(hookc_doc and recheck_platforms_built)
    if hookc_doc:
        if sidecar is None:
            rep["reason"] = "hookc sidecar given but not regenerated from this rebuild"
            return _finish(rep, out_dir, onledger)
        for plat, bt, mt in per_twin:
            try:
                ok, why, rep["metadata_diff"] = sidecar(bt, mt, [p for p, _ in twins] if rechecked else None)
            except Exception as e:  # a sidecar that cannot be regenerated is not confirmed
                rep["reason"] = "sidecar regeneration failed%s: %s: %s" % (
                    " (%s twin)" % plat if plat else "", type(e).__name__, str(e)[:1500])
                return _finish(rep, out_dir, onledger)
            if not ok:
                rep["verdict"] = "MISMATCH"
                rep["reason"] = "bytes match the chain but the %s%s" % ("(%s twin) " % plat if plat else "", why)
                return _finish(rep, out_dir, onledger)
        dc = rep["definition_check"] = definition_check(metadata["doc"], f["reads"])
        if "fields" not in dc:
            rep["reason"] = "cannot check the sidecar against the HookDefinition: " + dc["note"]
            return _finish(rep, out_dir, onledger)
        bad = [r for r in dc["fields"] if r["enforced"] and r["match"] is False]
        if bad:
            rep["verdict"] = "MISMATCH"
            rep["reason"] = "bytes match the chain but HookDefinition disagrees with the sidecar: " + "; ".join(
                "%s %s != %s %s" % (r["definition"], r["definition_value"], r["metadata"], r["metadata_value"]) for r in bad)
            return _finish(rep, out_dir, onledger)
    rep["verdict"] = "REPRODUCED"
    rep["reason"] = "rebuild is byte-identical to on-ledger CreateCode (SHA512Half %s)" % rep["hookhash"]
    if hookc_doc:
        rep["platforms_built_rechecked"] = rechecked
        claim = "+".join(metadata.get("platforms_built") or [])
        rep["reason"] += "; sidecar regenerated byte-identical; " + definition_summary(rep["definition_check"]["fields"])
        rep["reason"] += ("; builder.platforms_built %s re-checked (every twin rebuilt twice)" % claim if rechecked
                          else "; builder.platforms_built %s is the original build's record, NOT re-checked: this "
                               "verify rebuilt only %s (--platform)" % (claim, "+".join(p for p, _ in twins if p)))
    return _finish(rep, out_dir, onledger)


def definition_summary(rows):
    """Reason text built ONLY from rows as they came out: enforced rows that were compared
    and equal, enforced rows that could not be compared, and informational rows."""
    agree = [r["definition"] + (" (absent, WCE.cbak 0)" if r.get("expected") == ABSENT else "")
             for r in rows if r["enforced"] and r["match"] is True]
    absent = [r["definition"] for r in rows if r["enforced"] and r["match"] is None]
    info = ["%s %s" % (r["definition"], {True: "equal", False: "differs", None: "not compared"}[r["match"]])
            for r in rows if not r["enforced"]]
    parts = ["HookDefinition %s equal to the sidecar (enforced)" % "/".join(agree) if agree
             else "no enforced HookDefinition field was compared"]
    if absent:
        parts.append("%s not compared (sidecar WCE is null)" % "/".join(absent))
    if info:
        parts.append("informational: " + ", ".join(info))
    return "; ".join(parts)


ABSENT = "(absent)"


def fee_row(mk, wce, dk, dv, absent_when_zero):
    """One enforced row. SetHook (xahaud SetHook.cpp @bb244ef:1873-1881; genesis Change.cpp
    :679-684 likewise) ALWAYS writes Fee = computeExecutionFee(WCE.hook) (= WCE.hook,
    applyHook.cpp :696-703) and writes HookCallbackFee = computeExecutionFee(WCE.cbak) ONLY
    `if (maxInstrCountCbak > 0)`. So: WCE unknown (null) -> not compared; WCE.cbak 0 -> the
    definition must have NO HookCallbackFee; any other value -> the field must be present and
    equal. An absent field is compared, never skipped."""
    row = {"metadata": mk, "definition": dk, "metadata_value": wce,
           "definition_value": ABSENT if dv is None else dv, "enforced": True}
    if wce is None:
        return dict(row, expected=None, match=None)
    expected = None if (absent_when_zero and wce == 0) else str(wce)
    return dict(row, expected=ABSENT if expected is None else expected,
                match=(dv is None) if expected is None else (dv is not None and str(dv) == expected))


def definition_check(doc, reads):
    """hookc metadata vs the HookDefinition fields SetHook derived. Fee/HookCallbackFee are
    computeExecutionFee(validateGuards WCE) and are enforced (see fee_row for when
    HookCallbackFee is absent); HookOn and HookCanEmit are the first installer's choice and
    are reported only. Operators are compared on these four fields only (ReferenceCount etc.
    may change)."""
    defs = [{k: (r.get("definition") or {}).get(k) for k in DEFINITION_FIELDS} for r in reads]
    if not defs or any(d != defs[0] for d in defs[1:]):
        return {"note": "operators returned different HookDefinition Fee/HookCallbackFee/HookOn/HookCanEmit; not compared"}
    d = defs[0]
    wce = doc.get("WCE") or {}
    out = [fee_row("WCE.hook", wce.get("hook"), "Fee", d.get("Fee"), False),
           fee_row("WCE.cbak", wce.get("cbak"), "HookCallbackFee", d.get("HookCallbackFee"), True)]
    for mk, mv, dk, dv in (("HookOn", doc.get("HookOn"), "HookOn", d.get("HookOn")),
                           ("HookCanEmit", doc.get("HookCanEmit"), "HookCanEmit", d.get("HookCanEmit"))):
        row = {"metadata": mk, "definition": dk, "metadata_value": mv, "definition_value": dv,
               "enforced": dk in ENFORCED_DEFINITION_FIELDS}
        if mv is None or dv is None:
            out.append(dict(row, match=None))
        else:
            out.append(dict(row, match=str(mv).upper() == str(dv).upper()))
    return {"note": "Fee/HookCallbackFee enforced whenever the sidecar has a WCE (SetHook writes HookCallbackFee only "
                    "when WCE.cbak > 0, SetHook.cpp @bb244ef:1877); HookOn/HookCanEmit informational "
                    "(the creating SetHook's values, SetHook.cpp @bb244ef:1845-1848)",
            "fields": out}


def _finish(rep, out_dir, onledger):
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        if onledger is not None:
            with open(os.path.join(out_dir, "onledger.wasm"), "wb") as fh:
                fh.write(onledger)
        with open(os.path.join(out_dir, "verify-report.json"), "w") as fh:
            json.dump(rep, fh, indent=2, sort_keys=True)
    return rep

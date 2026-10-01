"""Offline tests for hookc (deterministic C hook builds + rshooks-compatible metadata).

Expected values are LITERALS from outside the package:
  - HookOn / HookCanEmit masks: the author's own installHook.js (Ekiserrepe/cron-claimreward-xahau
    @cd298ce, fixture claimreward_installHook.js), the rshooks v0.2.3 book sidecar and a recorded
    rshooks firewall sidecar;
  - WCE 149/7: the mainnet HookDefinition's Fee / HookCallbackFee (rec_xahau.network.json);
  - HookHash: the ledger's own HookHash field;
  - tx-type codes: xahaud hook/tts.h @bb244ef (fixture tts.h, sha256 5baa7ca0...);
  - tree hash e72ce8ff...: `find | sort | printf 'path\\0sha256\\n' | shasum -a 256` over fixtures/tree.
The one recorded package output is claimreward_0.hook.metadata.json (a real `hookc build`)."""
import copy
import json
import os
import re
import shutil
import subprocess

import pytest

from hook_repro import build as B, cli, hookc as HC, rshooks_meta as RM, verify as V
from hook_repro.hashing import sha512half

FX = os.path.join(os.path.dirname(__file__), "fixtures")
HX = os.path.join(FX, "hookc")
OPT_LOG = "HOOKC_WASM_OPT_RAN=1\n"  # the pipeline's own statement that wasm-opt ran (RT3 R3-02)
H_CR = "805351CE26FB79DA00647CEFED502F7E15C2ACCCE254F11DEFEDDCE241F8E9CA"
TREE_FX = "e72ce8ff02719def6b93b91bdc7e61653bcb7c24ccfea12a140c39c17c7b204c"
CR_COMMIT = "0a10b61b4f361384395a00ebc56e585f8389627f"
CR_TREE = "ce026102306391a66f310e4838958481596277db"
# on-ledger HookDefinition HookCanEmit (recorded fixtures rec_*.json)
DEF_CANEMIT = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFFFFFFFFFFFFFFFFBFFFF"


def rd(*p):
    with open(os.path.join(*p), "rb") as f:
        return f.read()


def meta_doc():
    return json.loads(rd(HX, "claimreward_0.hook.metadata.json"))


def install_js_masks():
    js = rd(HX, "claimreward_installHook.js").decode()
    return (re.search(r'"HookOn": "([0-9A-F]{64})"', js).group(1),
            re.search(r'"HookCanEmit": "([0-9A-F]{64})"', js).group(1))


def write_meta(tmp_path, doc, name="m.json"):
    p = tmp_path / name
    p.write_text(HC.dumps(doc))
    return str(p)


# ---------------- masks + tx table ----------------

def test_masks_match_author_install_script():
    on, can = install_js_masks()
    assert HC.hook_mask(["Cron"]) == on
    assert HC.hook_mask(["ClaimReward"]) == can


def test_masks_match_rshooks_sidecars():
    fw = json.loads(rd(FX, "rshooks", "recorded_firewall_0.main.metadata.json"))
    book = json.loads(rd(FX, "rshooks", "book_accept_all.metadata.json"))
    assert HC.hook_mask(fw["human"]["on"]["HookOn"]) == fw["HookOn"]
    assert HC.hook_mask(book["human"]["on"]["HookOn"]) == book["HookOn"]
    assert HC.hook_mask(None) is None


def test_mask_sethook_bit_is_inverted():
    # canHook: field ^= bit[ttHOOK_SET]; ~field. An empty list = fire on nothing.
    assert HC.hook_mask([]) == "F" * 58 + "BFFFFF"
    assert HC.decode_mask(HC.hook_mask([])) == []
    assert HC.hook_mask(["SetHook"]) == "F" * 64


def test_decode_onledger_canemit():
    assert HC.decode_mask(DEF_CANEMIT) == ["CheckCancel", "SetHook", "ClaimReward"]
    assert HC.decode_mask(install_js_masks()[1]) == ["ClaimReward"]


def test_tx_table_equals_xahaud_tts_h():
    tts = rd(HX, "tts.h").decode()
    codes = {int(c) for c in re.findall(r"^#define tt[A-Z_0-9]+ (\d+)$", tts, re.M)}
    assert len(codes) == 74 and set(HC.TX_TYPES.values()) == codes
    assert HC.TX_TYPES["ClaimReward"] == 98 and HC.TX_TYPES["Cron"] == 92 and HC.TX_TYPES["Invoke"] == 99


# ---------------- declarations ----------------

def test_decls_defaults_are_no_override():
    d, w = HC.normalize_decls({})
    assert d == {"index": 0, "name": None, "description": None, "on_form": "omitted", "on": None, "can_emit": None}
    assert w == []
    assert HC.normalize_decls({"on": "all"})[0]["on_form"] == "all"


@pytest.mark.parametrize("bad", [
    {"index": 10}, {"index": -1}, {"index": True}, {"index": "0"},
    {"on": ["Paymnet"]}, {"on": ["Payment", "Payment"]}, {"on": "Payment"},
    {"can_emit": ["X"]}, {"can_emit": "all"}, {"name": ""}, {"name": "x" * 33}, {"name": 5},
    {"description": 1}, {"HookOn": "FF"},
])
def test_decls_refused(bad):
    with pytest.raises(HC.HookcError):
        HC.normalize_decls(bad)


def test_decls_hookname_byte_warning():
    assert HC.normalize_decls({"name": "ab"})[1]
    assert HC.normalize_decls({"name": "abcd"})[1] == []


def test_load_decls_toml(tmp_path):
    p = tmp_path / "hookc.toml"
    p.write_text('[hook]\nindex = 2\nname = "claimrwd"\non = ["Cron"]\ncan_emit = []\n')
    d, _ = HC.load_decls(str(p), {"description": "x"})
    assert (d["index"], d["on"], d["can_emit"], d["description"]) == (2, ["Cron"], [], "x")
    p.write_text('[other]\nx = 1\n')
    with pytest.raises(HC.HookcError):
        HC.load_decls(str(p))
    p.write_text('[hook\n')
    with pytest.raises(HC.HookcError):
        HC.load_decls(str(p))


def test_parse_tx_arg():
    assert HC.parse_tx_arg(None) is None
    assert HC.parse_tx_arg("all") == "all"
    assert HC.parse_tx_arg("") == []
    assert HC.parse_tx_arg("Payment, Invoke") == ["Payment", "Invoke"]


# ---------------- metadata schema + rshooks compatibility ----------------

RSHOOKS_KEYS = ["index", "hook_fn", "cbak_fn", "name", "description", "HookOn", "HookCanEmit",
                "HookName", "HookHash", "WCE", "builder", "human", "chain"]


def test_metadata_schema_is_rshooks_superset():
    doc = meta_doc()
    for fx in ("recorded_firewall_0.main.metadata.json", "book_accept_all.metadata.json"):
        rs = json.loads(rd(FX, "rshooks", fx))
        assert list(rs)[:len(RSHOOKS_KEYS)] == RSHOOKS_KEYS
        assert list(doc)[:len(RSHOOKS_KEYS)] == RSHOOKS_KEYS  # same keys, same order
        assert list(doc["WCE"]) == list(rs["WCE"]) == ["hook", "cbak"]
        assert list(doc["human"]) == list(rs["human"])
        assert list(doc["human"]["on"]) == list(rs["human"]["on"])
        for k in ("index", "HookHash"):
            assert type(doc[k]) is type(rs[k])
    assert list(doc)[len(RSHOOKS_KEYS):] == ["source"]


def test_metadata_claimreward_values_are_chain_values():
    doc = meta_doc()
    on, can = install_js_masks()
    assert doc["HookHash"] == H_CR
    assert doc["WCE"] == {"hook": 149, "cbak": 7}  # HookDefinition Fee / HookCallbackFee on mainnet
    assert (doc["HookOn"], doc["HookCanEmit"]) == (on, can)
    assert doc["cbak_fn"] == "cbak" and doc["hook_fn"] == "hook" and doc["chain"] is None
    s = doc["source"]
    assert s["vcs"] == {"type": "git", "commit": CR_COMMIT, "path": "", "tree": CR_TREE, "dirty": False}
    assert doc["builder"]["platforms"]["linux/amd64"]["recipe_digest"] == \
        "13455c906e3c01aca7a51973acac2600cc34393582e7a3dddeb8fa33f2256b81"  # case study recipe digest (RT4 F1)


def test_dumps_matches_serde_pretty_format():
    # rshooks-build writes serde_json::to_vec_pretty + "\n"; hookc must format identically
    for fx in ("recorded_firewall_0.main.metadata.json",):
        raw = rd(FX, "rshooks", fx).decode()
        assert HC.dumps(json.loads(raw)) == raw
    raw = rd(HX, "claimreward_0.hook.metadata.json").decode()
    assert HC.dumps(json.loads(raw)) == raw and raw.endswith("}\n")


def test_metadata_has_no_host_specific_values():
    raw = rd(HX, "claimreward_0.hook.metadata.json").decode()
    for bad in ("/Users/", "/home/", "/private/", "2026-", "image_id"):
        assert bad not in raw


def test_rshooks_parser_refuses_hookc_metadata_and_cli_dispatches(tmp_path):
    p = write_meta(tmp_path, meta_doc())
    with pytest.raises(RM.MetadataError):
        RM.load_metadata(p)
    assert cli._builder_name(p) == "hookc"
    recipe, params, meta = cli.resolve_recipe(None, {}, p, "linux/amd64")
    assert recipe == "xhc-bin127" and params == {"CLANG_OPT": "-O2", "STAGES": "opt,clean", "WASMOPT": "-O2"}
    assert meta["hookhash"] == H_CR and meta["preset"] == "classic"


def test_cli_refuses_contradicting_flags(tmp_path):
    p = write_meta(tmp_path, meta_doc())
    with pytest.raises(HC.HookcError):
        cli.resolve_recipe("kvt-llvm22", {}, p, "linux/amd64")
    with pytest.raises(HC.HookcError):
        cli.resolve_recipe(None, {"CLANG_OPT": "-O3"}, p, "linux/amd64")


def test_parse_metadata_accepts_recorded():
    m = HC.parse_metadata(meta_doc())
    assert m["toolchain"] == "xhc-bin127" and m["entry"] == "0.hook" and m["index"] == 0


def _mut(path, value):
    def f(d):
        cur = d
        for k in path[:-1]:
            cur = cur[k]
        if value is KeyError:
            del cur[path[-1]]
        else:
            cur[path[-1]] = value
    return f


@pytest.mark.parametrize("name,mut", [
    ("no source block", _mut(["source"], KeyError)),
    ("source null", _mut(["source"], None)),
    ("vcs null", _mut(["source", "vcs"], None)),
    ("vcs not git", _mut(["source", "vcs", "type"], "hg")),
    ("dirty", _mut(["source", "vcs", "dirty"], True)),
    ("dirty missing", _mut(["source", "vcs", "dirty"], KeyError)),
    ("short commit", _mut(["source", "vcs", "commit"], CR_COMMIT[:12])),
    ("bad tree", _mut(["source", "vcs", "tree"], "x" * 40)),
    ("escaping path", _mut(["source", "vcs", "path"], "../x")),
    ("tree sha missing", _mut(["source", "tree_sha256"], KeyError)),
    ("tree sha upper", _mut(["source", "tree_sha256"], TREE_FX.upper())),
    ("bad entry", _mut(["source", "entry"], "../x.c")),
    ("rshooks builder", _mut(["builder", "name"], "rshooks-build")),
    ("other version", _mut(["builder", "version"], "0.0.9")),
    ("unknown toolchain", _mut(["builder", "toolchain"], "gcc")),
    ("params not strings", _mut(["builder", "params"], {"CLANG_OPT": 2})),
    ("no platforms", _mut(["builder", "platforms"], {})),
    ("lower HookHash", _mut(["HookHash"], H_CR.lower())),
    ("index 10", _mut(["index"], 10)),
    ("index bool", _mut(["index"], False)),
    ("hook_fn main", _mut(["hook_fn"], "main")),
    ("bad HookOn", _mut(["HookOn"], "FF")),
    ("bad HookCanEmit", _mut(["HookCanEmit"], "G" * 64)),
])
def test_parse_metadata_refuses(name, mut):
    d = meta_doc()
    mut(d)
    with pytest.raises(HC.HookcError):
        HC.parse_metadata(d)


def test_parse_metadata_refuses_non_object():
    with pytest.raises(HC.HookcError):
        HC.parse_metadata([])


def test_select_platform_pins(tmp_path):
    m = HC.parse_metadata(meta_doc())
    assert HC.select_platform(m, "linux/amd64") == ("linux/amd64", "xhc-bin127")
    assert HC.select_platform(m) == ("linux/amd64", "xhc-bin127")  # only twin listed
    with pytest.raises(HC.HookcError):
        HC.select_platform(m, "linux/arm64")  # bin.zip toolchain is x86_64-only
    d = meta_doc(); d["builder"]["platforms"]["linux/amd64"]["recipe_digest"] = "0" * 64
    with pytest.raises(HC.HookcError):  # toolchain drift
        HC.select_platform(HC.parse_metadata(d), "linux/amd64")
    d = meta_doc(); d["builder"]["platforms"]["linux/amd64"]["recipe"] = "kvt-llvm22-amd64"
    with pytest.raises(HC.HookcError):
        HC.select_platform(HC.parse_metadata(d), "linux/amd64")


def test_platform_pins_cover_both_llvm_twins():
    p = HC.platform_pins("kvt-llvm22")
    assert sorted(p) == ["linux/amd64", "linux/arm64"]
    assert p["linux/arm64"]["recipe_digest"] == "0daccbce80f39f1d7051bb416e7362569389e97cd620dd6eb66d45a2642917ef"
    assert p["linux/amd64"]["base_image"] == \
        "python@sha256:1aaa65a85fda306ffb8b910824d4e93bdce61e212c7e87168123ea3073b41a1a"
    shas = {a["name"]: a["sha256"] for a in p["linux/amd64"]["artifacts"]}
    assert shas["llvm"] == "edb0522b41e261819c06ea437d249f9b8acfa413d3805bc9920eec6fb76ff830"  # GitHub asset digest
    assert list(HC.platform_pins("xhc-bin127")) == ["linux/amd64"]


def test_platform_pins_refuse_mislabelled_twin(monkeypatch):
    monkeypatch.setitem(HC.TOOLCHAINS, "kvt-llvm22", dict(HC.TOOLCHAINS["kvt-llvm22"], platforms={
        "linux/arm64": "kvt-llvm22-amd64", "linux/amd64": "kvt-llvm22"}))
    with pytest.raises(HC.HookcError):
        HC.platform_pins("kvt-llvm22")


def test_amd64_twin_runs_the_same_pipeline():
    a, b = (B.load_recipe(n) for n in ("kvt-llvm22", "kvt-llvm22-amd64"))
    for fn in ["pipeline.sh", "guard_hoist.py"]:
        assert rd(a["_dir"], fn) == rd(b["_dir"], fn)
    assert a["params"] == b["params"] and a["presets"] == b["presets"]


# ---------------- WCE ----------------

def test_parse_wce_output():
    assert HC.parse_wce_output("0", '{"valid":true,"hook":149,"cbak":7}') == ({"hook": 149, "cbak": 7}, None)
    with pytest.raises(HC.HookcError):
        HC.parse_wce_output("1", '{"valid":false}', "GuardCheck Missing guard")
    for rc, txt in (("0", "garbage"), ("0", '{"valid":true,"hook":-1,"cbak":0}'),
                    ("0", '{"valid":true,"hook":true,"cbak":0}'), ("0", '{"valid":true,"hook":1}'),
                    ("2", '{"valid":false,"threw":true}'), ("0", '{"valid":false}'), ("1", '{"valid":true,"hook":1,"cbak":0}')):
        w, why = HC.parse_wce_output(rc, txt)
        assert w is None and why


def test_wce_pin_names_xahaud_headers():
    p = HC.wce_pin()
    assert p["xahaud_commit"] == "bb244ef7729503a0317bcff0f8fdaa93ca5cb7d2"
    assert p["headers"]["Guard.h"] == "705e7e9cf8b2e02f0a031a86ad9ddd292ba19e838a14f7a4e5a23c93e6d6c518"


# ---------------- make_metadata ----------------

DECLS_CR = {"index": 0, "name": None, "description": None, "on_form": "list", "on": ["Cron"], "can_emit": ["ClaimReward"]}
PARAMS_CR = {"CLANG_OPT": "-O2", "STAGES": "opt,clean", "WASMOPT": "-O2"}


def regen(wasm, wce={"hook": 149, "cbak": 7}):
    doc = meta_doc()
    return HC.make_metadata(DECLS_CR, wasm, wce, None, "xhc-bin127", "classic", PARAMS_CR,
                            rd(HX, "claimreward_build.txt").decode(), doc["source"], ["linux/amd64"])


def test_make_metadata_regenerates_recorded_bytes():
    assert HC.dumps(regen(rd(FX, "claimreward_onledger.wasm"))) == rd(HX, "claimreward_0.hook.metadata.json").decode()


def test_make_metadata_wce_null_with_reason():
    # RT4 F3b: the only null-WCE reason is the fixed, host-independent --no-wce string
    d = HC.make_metadata(DECLS_CR, rd(FX, "claimreward_onledger.wasm"), None, "WCE not computed (--no-wce)",
                         "xhc-bin127", "classic", PARAMS_CR, OPT_LOG, meta_doc()["source"], ["linux/amd64"])
    assert d["WCE"] == {"hook": None, "cbak": None} and d["builder"]["wce"]["reason"] == "WCE not computed (--no-wce)"


def test_make_metadata_on_all_and_name():
    d = HC.make_metadata(dict(DECLS_CR, on_form="all", on=None, name="claimrwd"), rd(FX, "claimreward_onledger.wasm"),
                         None, HC.NO_WCE_REASON, "xhc-bin127", "classic", PARAMS_CR, OPT_LOG, meta_doc()["source"], ["linux/amd64"])
    assert d["HookOn"] == "0" * 64 and d["HookName"] == "636C61696D727764"


def test_make_metadata_refuses_bad_exports():
    tiny = rd(FX, "tiny.wasm")  # exports only hook
    d = HC.make_metadata(DECLS_CR, tiny, None, HC.NO_WCE_REASON, "xhc-bin127", "classic", PARAMS_CR, OPT_LOG, meta_doc()["source"], ["linux/amd64"])
    assert d["cbak_fn"] is None
    exp = b"\x07\x08\x01\x04hook\x00\x01"  # export section of tiny.wasm (wat2wasm)
    assert tiny.count(exp) == 1
    only_cbak = tiny.replace(exp, b"\x07\x08\x01\x04cbak\x00\x01")
    with pytest.raises(HC.HookcError, match="no `hook`"):
        HC.make_metadata(DECLS_CR, only_cbak, None, HC.NO_WCE_REASON, "xhc-bin127", "classic", PARAMS_CR, "", {}, ["linux/amd64"])
    extra = tiny.replace(exp, b"\x07\x0f\x02\x04hook\x00\x01\x04fooo\x00\x01")
    assert HC.exports_of(extra)[0] == ["fooo", "hook"]
    with pytest.raises(HC.HookcError, match="other than exactly `hook` and `cbak`"):
        HC.make_metadata(DECLS_CR, extra, None, HC.NO_WCE_REASON, "xhc-bin127", "classic", PARAMS_CR, "", {}, ["linux/amd64"])
    with pytest.raises(HC.HookcError):
        HC.make_metadata(DECLS_CR, b"\x00asm", None, HC.NO_WCE_REASON, "xhc-bin127", "classic", PARAMS_CR, "", {}, ["linux/amd64"])


def test_emit_warnings():
    d = regen(rd(FX, "claimreward_onledger.wasm"))
    assert HC.emit_warnings(d, rd(FX, "claimreward_onledger.wasm")) == []
    d["human"]["HookCanEmit"] = []
    assert HC.emit_warnings(d, rd(FX, "claimreward_onledger.wasm"))
    d2 = HC.make_metadata(DECLS_CR, rd(FX, "tiny.wasm"), None, HC.NO_WCE_REASON, "xhc-bin127", "classic", PARAMS_CR, OPT_LOG, {}, ["linux/amd64"])
    assert HC.emit_warnings(d2, rd(FX, "tiny.wasm"))  # can_emit declared, no emit import


def test_metadata_diff():
    a = meta_doc(); b = copy.deepcopy(a)
    assert HC.metadata_diff(a, b) == []
    b["WCE"]["hook"] = 150; b["extra"] = 1
    assert HC.metadata_diff(a, b) == ["WCE.hook", "extra"]
    assert HC.metadata_diff({"x": 1}, {"x": True}) == ["x"]


# ---------------- reproduce (builder stubbed; real bytes) ----------------

def fx_repo(tmp_path):
    """fixtures/tree committed to a fresh git repo; its source block from git + the literal TREE_FX."""
    r = tmp_path / "fxrepo"
    shutil.copytree(os.path.join(FX, "tree"), str(r))
    git(tmp_path, "init", "-q", str(r))
    git(r, "add", "-A")
    git(r, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "fx")
    return str(r), {"vcs": {"type": "git", "commit": git(r, "rev-parse", "HEAD"), "path": "",
                            "tree": git(r, "rev-parse", "HEAD^{tree}"), "dirty": False},
                    "tree_sha256": TREE_FX, "file_count": 4, "entry": None}


def fx_meta(tmp_path, **changes):
    repo, sb = fx_repo(tmp_path)
    d = meta_doc()
    d["source"] = sb
    for k, v in changes.items():
        d[k] = v
    return write_meta(tmp_path, d), repo


def stub(monkeypatch, outputs, wce=({"hook": 149, "cbak": 7}, None)):
    it = iter(outputs)

    def fake_build(src, recipe, params, preset, out_dir, log=None):
        w = next(it)
        return ({"params": dict(params), "container_log": rd(HX, "claimreward_build.txt").decode(),
                 "recipe": {"name": recipe, "digest": "d"}, "image": {"image_id": "i"},
                 "source": {"tree_sha256": HC.tree_hash(src)[0]}}, w)
    monkeypatch.setattr(B, "build", fake_build)
    monkeypatch.setattr(HC, "run_wce", lambda w, log=None: wce)


def test_reproduce_round_trip(tmp_path, monkeypatch):
    w = rd(FX, "claimreward_onledger.wasm")
    stub(monkeypatch, [w, w])
    m, repo = fx_meta(tmp_path)
    rep = HC.reproduce(m, src=repo, platform="linux/amd64",
                       ref_wasm=os.path.join(FX, "claimreward_onledger.wasm"), out_dir=str(tmp_path / "o"))
    assert rep["verdict"] == "REPRODUCED" and rep["metadata_diff"] == []


def test_reproduce_one_byte_difference_is_mismatch(tmp_path, monkeypatch):
    w = bytearray(rd(FX, "claimreward_onledger.wasm"))
    w[0x130] = 0x21  # i32.const operand inside func[10] hook
    stub(monkeypatch, [bytes(w), bytes(w)])
    m, repo = fx_meta(tmp_path)
    rep = HC.reproduce(m, src=repo, platform="linux/amd64",
                       ref_wasm=os.path.join(FX, "claimreward_onledger.wasm"), out_dir=str(tmp_path / "o"))
    assert rep["verdict"] == "MISMATCH" and V.EXIT[rep["verdict"]] == 2
    assert rep["diff"]["bytes_differing"] == 1
    assert [s["section"] for s in rep["diff"]["sections"] if s["status"] != "same"] == ["code"]


def test_reproduce_nondeterministic_refused(tmp_path, monkeypatch):
    w = rd(FX, "claimreward_onledger.wasm")
    stub(monkeypatch, [w, rd(FX, "claimreward_nearmiss_808.wasm")])
    with pytest.raises(HC.HookcError, match="NOT DETERMINISTIC"):
        m, repo = fx_meta(tmp_path)
        HC.reproduce(m, git=repo, platform="linux/amd64", out_dir=str(tmp_path / "o"))


def test_reproduce_metadata_tamper_is_mismatch(tmp_path, monkeypatch):
    w = rd(FX, "claimreward_onledger.wasm")
    stub(monkeypatch, [w, w])
    m, repo = fx_meta(tmp_path, WCE={"hook": 150, "cbak": 7})
    rep = HC.reproduce(m, src=repo, platform="linux/amd64", out_dir=str(tmp_path / "o"))
    assert rep["verdict"] == "MISMATCH" and rep["metadata_diff"] == ["WCE.hook"]


def test_reproduce_formatting_tamper_is_mismatch(tmp_path, monkeypatch):
    w = rd(FX, "claimreward_onledger.wasm")
    stub(monkeypatch, [w, w])
    p, repo = fx_meta(tmp_path)
    with open(p) as f:
        t = f.read()
    with open(p, "w") as f:
        f.write(t.rstrip("\n"))
    rep = HC.reproduce(p, src=repo, platform="linux/amd64", out_dir=str(tmp_path / "o"))
    assert rep["verdict"] == "MISMATCH"


def test_reproduce_refuses_foreign_reference_and_source(tmp_path, monkeypatch):
    w = rd(FX, "claimreward_onledger.wasm")
    stub(monkeypatch, [w, w])
    m, repo = fx_meta(tmp_path)
    rep = HC.reproduce(m, src=repo, platform="linux/amd64", ref_wasm=os.path.join(FX, "tiny.wasm"))
    assert rep["verdict"] == "UNVERIFIED"
    with pytest.raises(HC.HookcError):  # the recorded sidecar's commit is not in this repo
        HC.reproduce(write_meta(tmp_path, meta_doc(), "orig.json"), git=repo, platform="linux/amd64")
    with pytest.raises(HC.HookcError):  # HEAD tree is not the recorded sidecar's tree
        HC.reproduce(write_meta(tmp_path, meta_doc(), "orig.json"), src=repo, platform="linux/amd64")


def test_decls_from_human():
    assert HC.decls_from_human(meta_doc()) == DECLS_CR
    for bad in ({"human": None}, {"human": {"on": {"form": "sometimes"}}},
                {"human": {"on": {"form": "list", "HookOn": None}, "HookCanEmit": None, "HookName": None}},
                {"human": {"on": {"form": "list", "HookOn": ["Nope"]}, "HookCanEmit": None, "HookName": None}}):
        d = meta_doc(); d.update(bad)
        with pytest.raises(HC.HookcError):
            HC.decls_from_human(d)
    d = meta_doc(); d["human"]["on"] = {"form": "all"}
    assert HC.decls_from_human(d)["on_form"] == "all"


def test_reproduce_human_mask_disagreement_is_mismatch(tmp_path, monkeypatch):
    w = rd(FX, "claimreward_onledger.wasm")
    stub(monkeypatch, [w, w])
    repo, sb = fx_repo(tmp_path)
    d = meta_doc(); d["source"] = sb
    d["human"]["HookCanEmit"] = ["ClaimReward", "Payment"]  # readable form disagrees with the mask
    rep = HC.reproduce(write_meta(tmp_path, d), src=repo, platform="linux/amd64",
                       out_dir=str(tmp_path / "o"))
    assert rep["verdict"] == "MISMATCH" and "HookCanEmit" in rep["metadata_diff"]


def test_reproduce_refuses_missing_provenance(tmp_path):
    d = meta_doc(); d["source"]["vcs"] = None
    with pytest.raises(HC.HookcError, match="provenance"):
        HC.reproduce(write_meta(tmp_path, d), src=str(tmp_path))


# ---------------- source provenance ----------------

def git(repo, *a):
    return subprocess.run(["git", "-C", str(repo)] + list(a), check=True, capture_output=True, text=True).stdout.strip()


def mkrepo(tmp_path):
    r = tmp_path / "repo"
    (r / "h").mkdir(parents=True)
    (r / "h" / "a.c").write_bytes(b"int x;\r\nint y;\n")  # CRLF must survive export untouched
    (r / "top.txt").write_text("t")
    git(r.parent, "init", "-q", str(r))
    git(r, "config", "core.autocrlf", "true")
    git(r, "add", "h/a.c", "top.txt")
    git(r, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "c")
    return r


def test_export_git_exact_blobs(tmp_path):
    r = mkrepo(tmp_path)
    blob = subprocess.run(["git", "-C", str(r), "cat-file", "blob", "HEAD:h/a.c"], capture_output=True).stdout
    v = HC.export_git(str(r), "HEAD", "h", str(tmp_path / "out"))
    assert (tmp_path / "out" / "a.c").read_bytes() == blob
    assert v == {"type": "git", "commit": git(r, "rev-parse", "HEAD"), "path": "h",
                 "tree": git(r, "rev-parse", "HEAD:h"), "dirty": False}
    assert sorted(os.listdir(tmp_path / "out")) == ["a.c"]


def test_export_git_refuses_symlink_and_bad_path(tmp_path):
    r = mkrepo(tmp_path)
    os.symlink("a.c", str(r / "h" / "l.c"))
    git(r, "add", "h/l.c")
    git(r, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "l")
    with pytest.raises(HC.HookcError):
        HC.export_git(str(r), "HEAD", "h", str(tmp_path / "o1"))
    for bad in ("../x", "h/..", "./h", "h//a", "/h", "h/"):
        with pytest.raises(HC.HookcError):
            HC.export_git(str(r), "HEAD", bad, str(tmp_path / "o2"))
    assert HC.REL_RE.match("a/.hidden/b..c")
    # a path git accepts but the metadata grammar does not must be refused before export
    (r / "my dir").mkdir(); (r / "my dir" / "b.c").write_text("x")
    git(r, "add", "my dir/b.c")
    git(r, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "sp")
    assert git(r, "rev-parse", "HEAD:my dir")
    with pytest.raises(HC.HookcError, match="bad source path"):
        HC.export_git(str(r), "HEAD", "my dir", str(tmp_path / "o4"))
    with pytest.raises(HC.HookcError):
        HC.export_git(str(r), "HEAD", "top.txt", str(tmp_path / "o3"))


def test_vcs_of_dir_clean_dirty_untracked(tmp_path):
    r = mkrepo(tmp_path)
    v, why = HC.vcs_of_dir(str(r / "h"))
    assert why is None and v["path"] == "h" and v["tree"] == git(r, "rev-parse", "HEAD:h")
    (r / "h" / "new.c").write_text("x")
    v, why = HC.vcs_of_dir(str(r / "h"))
    assert v is None and "uncommitted" in why
    (r / "h" / "new.c").unlink()
    (r / "h" / "a.c").write_text("changed")
    assert HC.vcs_of_dir(str(r / "h"))[0] is None
    plain = tmp_path / "plain"; plain.mkdir()
    assert HC.vcs_of_dir(str(plain)) == (None, "not inside a git work tree")


def test_materialize_refuses_unversioned(tmp_path):
    plain = tmp_path / "plain"; plain.mkdir()
    with pytest.raises(HC.HookcError, match="no source provenance"):
        HC.materialize(src=str(plain))
    assert HC.materialize(src=str(plain), allow_unversioned=True) == (str(plain), None, None)


def test_params_for_entry():
    assert HC.params_for("kvt-llvm22", "a.c", {}) == {"ENTRY": "a.c"}
    assert HC.params_for("xhc-bin127", None, {"X": "1"}) == {"X": "1"}
    with pytest.raises(HC.HookcError):
        HC.params_for("xhc-bin127", "a.c", {})
    with pytest.raises(HC.HookcError):
        HC.params_for("kvt-llvm22", "a.c; rm", {})


def test_build_refuses_unknown_platform_twin(tmp_path):
    with pytest.raises(HC.HookcError, match="x86_64"):
        HC.build(src=str(tmp_path), tc_name="xhc-bin127", platforms=["linux/arm64"], out_dir=str(tmp_path))
    with pytest.raises(HC.HookcError):
        HC.toolchain("gcc")


def test_build_cross_platform_mismatch_refused(tmp_path, monkeypatch):
    w = rd(FX, "claimreward_onledger.wasm")
    stub(monkeypatch, [w, w, rd(FX, "claimreward_nearmiss_808.wasm"), rd(FX, "claimreward_nearmiss_808.wasm")])
    r = mkrepo(tmp_path)
    with pytest.raises(HC.HookcError, match="CROSS-PLATFORM MISMATCH"):
        HC.build(git=str(r), path="h", tc_name="kvt-llvm22", out_dir=str(tmp_path / "o"))


def test_build_writes_rshooks_style_files(tmp_path, monkeypatch):
    w = rd(FX, "claimreward_onledger.wasm")
    stub(monkeypatch, [w, w])
    r = mkrepo(tmp_path)
    meta, wasm, summ = HC.build(git=str(r), path="h", tc_name="xhc-bin127", decls=HC.normalize_decls({"index": 3})[0],
                                out_dir=str(tmp_path / "o"))
    assert sorted(os.listdir(tmp_path / "o")) == ["3.hook.metadata.json", "3.hook.wasm"]
    assert (tmp_path / "o" / "3.hook.wasm").read_bytes() == w and meta["index"] == 3
    assert meta["source"]["vcs"]["tree"] == git(r, "rev-parse", "HEAD:h") and meta["WCE"] == {"hook": 149, "cbak": 7}
    assert summ["HookHash"] == sha512half(w)


# ---------------- verify --metadata ----------------

def test_definition_check_against_recorded_mainnet():
    with open(os.path.join(FX, "rec_xahau.network.json")) as f:
        node = json.load(f)["ledger_entry"]["result"]["node"]
    reads = [{"definition": {k: v for k, v in node.items() if k != "CreateCode"}}] * 2
    rows = {r["definition"]: r["match"] for r in V.definition_check(meta_doc(), reads)["fields"]}
    assert rows == {"Fee": True, "HookCallbackFee": True, "HookOn": True, "HookCanEmit": False}
    other = [reads[0], {"definition": dict(reads[0]["definition"], Fee="1")}]
    assert "fields" not in V.definition_check(meta_doc(), other)


@pytest.mark.parametrize("mut,msg", [
    (_mut(["builder", "params"], {"CLANG_OPT": 2}), "map names to strings"),
    (_mut(["source", "entry"], "../x.c"), "is not a .c file name"),
])
def test_parse_metadata_refuses_with_the_specific_reason(mut, msg):
    # these checks run before the (RT round 1) resolution/entry checks; the reason must be theirs
    d = meta_doc()
    mut(d)
    with pytest.raises(HC.HookcError, match=msg):
        HC.parse_metadata(d)

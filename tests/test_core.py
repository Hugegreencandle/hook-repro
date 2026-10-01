"""Offline tests. Every expected hash below is a LITERAL computed outside the package
(shasum -a 512 / shasum -a 256 / the ledger's own HookHash field), never by hook_repro."""
import copy
import json
import os

import pytest

from hook_repro import bind, fetch, verify as V, wasm
from hook_repro.build import BuildError, load_recipe, resolve_params, recipe_digest
from hook_repro.hashing import TreeError, sha512half, tree_hash

FX = os.path.join(os.path.dirname(__file__), "fixtures")
H_CR = "805351CE26FB79DA00647CEFED502F7E15C2ACCCE254F11DEFEDDCE241F8E9CA"  # ledger HookHash field
H_TINY = "5D26689844FF7F624881E9FE0207EB28FE9D378CD569D62652AC7367AF8D70FB"  # shasum -a 512 tiny.wasm
H_NEAR = "21D23B4C5B1477BE6BAB4DEFB2EF3FADA3C78BBC48160F0AD1FE5136108F4F28"  # shasum -a 512 nearmiss
TINY_HEX = ("0061736d01000000010d0260037f7f7e017e60017f017e020e0103656e760661636365707400000302010107"
            "080104686f6f6b00010a0c010a0041004100420010000b")  # wat2wasm tiny.wat
MAIN = ["https://xahau.network", "https://cluster.cbotlabs.xyz"]


def rd(name):
    with open(os.path.join(FX, name), "rb") as f:
        return f.read()


def recorded():
    out = {}
    for host in ("xahau.network", "cluster.cbotlabs.xyz"):
        with open(os.path.join(FX, "rec_%s.json" % host)) as f:
            out["https://" + host] = json.load(f)
    return out


def transport_from(rec):
    def t(url, payload):
        r = rec[url]
        if isinstance(r, Exception):
            raise r
        return copy.deepcopy(r["server_info"] if payload["method"] == "server_info" else r["ledger_entry"])
    return t


# ---------------- hashing ----------------

def test_sha512half_literals():
    assert sha512half(bytes.fromhex(TINY_HEX)) == H_TINY
    assert sha512half(rd("tiny.wasm")) == H_TINY
    assert sha512half(rd("claimreward_onledger.wasm")) == H_CR
    assert sha512half(b"") == "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE"


def test_tree_hash_order_and_content(tmp_path):
    a = tmp_path / "a"; b = tmp_path / "b"
    for d, order in ((a, ["x.c", "y.h"]), (b, ["y.h", "x.c"])):
        d.mkdir()
        for n in order:
            (d / n).write_text("content of " + n)
    ha, la = tree_hash(str(a))
    hb, _ = tree_hash(str(b))
    assert ha == hb and [e[0] for e in la] == ["x.c", "y.h"]
    (b / "x.c").write_text("content of x.c ")
    assert tree_hash(str(b))[0] != ha
    (a / ".git").mkdir(); (a / ".git" / "HEAD").write_text("ignored")
    assert tree_hash(str(a))[0] == ha


def test_tree_hash_refuses_symlink(tmp_path):
    (tmp_path / "real.c").write_text("x")
    os.symlink(str(tmp_path / "real.c"), str(tmp_path / "link.c"))
    with pytest.raises(TreeError):
        tree_hash(str(tmp_path))


# ---------------- wasm ----------------

def test_parse_tiny():
    m = wasm.parse(rd("tiny.wasm"))
    assert [s["name"] for s in m["sections"]] == ["type", "import", "function", "export", "code"]
    assert m["n_imported_funcs"] == 1
    assert m["functions"][0]["name"] == "hook" and m["functions"][0]["index"] == 1


def test_parse_claimreward_functions():
    m = wasm.parse(rd("claimreward_onledger.wasm"))
    f = {x["name"]: x for x in m["functions"]}
    assert f["cbak"]["size"] == 14 and f["hook"]["size"] == 320  # wasm-objdump -x
    assert m["n_imported_funcs"] == 9
    assert len(m["exports"]) == 2


@pytest.mark.parametrize("bad", [b"", b"\x00asm", b"\x00asm\x02\x00\x00\x00", b"MZ\x90\x00\x01\x00\x00\x00",
                                 b"\x00asm\x01\x00\x00\x00\x01\x05\x01"])
def test_parse_rejects_malformed(bad):
    with pytest.raises(wasm.WasmError):
        wasm.parse(bad)


def test_diff_identical():
    d = wasm.diff(rd("claimreward_onledger.wasm"), rd("claimreward_onledger.wasm"))
    assert d["identical"] and d["first_diff_offset"] is None
    assert all(s["status"] == "same" for s in d["sections"])


def test_one_byte_build_diff_localised():
    a = rd("claimreward_onledger.wasm")
    b = bytearray(a)
    assert b[0x130] == 0x20  # `i32.const 32` operand inside func[10] hook (wasm-objdump -d)
    b[0x130] = 0x21
    d = wasm.diff(a, bytes(b))
    assert not d["identical"]
    assert d["first_diff_offset"] == 0x130 and d["bytes_differing"] == 1 and d["size_delta"] == 0
    changed = [s["section"] for s in d["sections"] if s["status"] != "same"]
    assert changed == ["code"]
    fchanged = [(f["index"], f["name"]) for f in d["functions"] if f["status"] != "same"]
    assert fchanged == [(10, "hook")]
    assert d["imports_equal"] and d["exports_equal"]


def test_nearmiss_diff_is_code_only_same_size():
    """Real near-miss: Builder-2025 pass list yields 808 B with renumbered locals."""
    near = rd("claimreward_nearmiss_808.wasm")
    assert sha512half(near) == H_NEAR
    d = wasm.diff(rd("claimreward_onledger.wasm"), near)
    assert d["size_delta"] == 0 and d["bytes_differing"] == 11
    assert [s["section"] for s in d["sections"] if s["status"] != "same"] == ["code"]
    assert {f["name"] for f in d["functions"] if f["status"] != "same"} == {"hook"}  # cmp -l offsets 308..608 all inside func[10] (0x128..0x268)


def test_diff_size_change_and_unparseable():
    d = wasm.diff(rd("tiny.wasm"), rd("claimreward_onledger.wasm"))
    assert d["size_delta"] == 808 - 67
    assert any(s["status"].startswith("only_") for s in d["sections"])
    d2 = wasm.diff(rd("tiny.wasm"), b"not wasm at all")
    assert not d2["identical"] and "parse_error" in d2


# ---------------- fetch ----------------

def test_fetch_two_operators_agree():
    f = fetch.fetch_createcode(H_CR, "mainnet", transport=transport_from(recorded()), endpoints=MAIN)
    assert f["ok"], f["reason"]
    assert f["distinct_operators"] == 2 and sha512half(f["code"]) == H_CR
    assert f["code"] == rd("claimreward_onledger.wasm")


def test_fetch_lowercase_hash_normalised():
    f = fetch.fetch_createcode(H_CR.lower(), "mainnet", transport=transport_from(recorded()), endpoints=MAIN)
    assert f["ok"]


def test_fetch_operator_disagreement_unverified():
    rec = recorded()
    node = rec[MAIN[1]]["ledger_entry"]["result"]["node"]
    cc = bytearray.fromhex(node["CreateCode"]); cc[0x130] ^= 1
    node["CreateCode"] = cc.hex().upper()
    f = fetch.fetch_createcode(H_CR, "mainnet", transport=transport_from(rec), endpoints=MAIN)
    assert not f["ok"] and "DISAGREE" in f["reason"] and f["code"] is None


def test_fetch_both_agree_but_hash_mismatch():
    rec = recorded()
    for url in MAIN:
        node = rec[url]["ledger_entry"]["result"]["node"]
        cc = bytearray.fromhex(node["CreateCode"]); cc[-1] ^= 1
        node["CreateCode"] = cc.hex()
    f = fetch.fetch_createcode(H_CR, "mainnet", transport=transport_from(rec), endpoints=MAIN)
    assert not f["ok"] and "SHA512Half" in f["reason"]


def test_fetch_read_failure_unverified():
    rec = recorded()
    rec[MAIN[0]] = fetch.RpcError("connection refused")
    f = fetch.fetch_createcode(H_CR, "mainnet", transport=transport_from(rec), endpoints=MAIN)
    assert not f["ok"] and f["reason"].startswith("read failure")


@pytest.mark.parametrize("mut,frag", [
    (lambda r: r["ledger_entry"]["result"].__setitem__("validated", False), "not validated"),
    (lambda r: r["ledger_entry"]["result"].update({"status": "error", "error": "entryNotFound"}), "entryNotFound"),
    (lambda r: r["ledger_entry"]["result"]["node"].__setitem__("LedgerEntryType", "Hook"), "not a HookDefinition"),
    (lambda r: r["ledger_entry"]["result"]["node"].pop("CreateCode"), "CreateCode missing"),
    (lambda r: r["ledger_entry"]["result"]["node"].__setitem__("CreateCode", "ZZ"), "not hex"),
    (lambda r: r["ledger_entry"]["result"]["node"].__setitem__("HookHash", "00" * 32), "HookHash field"),
    (lambda r: r["server_info"]["result"]["info"].pop("pubkey_node"), "pubkey_node"),
    (lambda r: r.__setitem__("ledger_entry", {"jsonrpc": "2.0"}), "malformed"),
])
def test_fetch_each_bad_response_unverified(mut, frag):
    rec = recorded()
    mut(rec[MAIN[1]])
    f = fetch.fetch_createcode(H_CR, "mainnet", transport=transport_from(rec), endpoints=MAIN)
    assert not f["ok"] and frag in f["reason"], f["reason"]


def test_fetch_wrong_network_id():
    rec = recorded()
    rec[MAIN[0]]["server_info"]["result"]["info"]["network_id"] = 21338
    f = fetch.fetch_createcode(H_CR, "mainnet", transport=transport_from(rec), endpoints=MAIN)
    assert not f["ok"] and "network_id" in f["reason"]


def test_fetch_same_node_refused_unless_allowed():
    rec = recorded()
    rec[MAIN[1]]["server_info"]["result"]["info"]["pubkey_node"] = \
        rec[MAIN[0]]["server_info"]["result"]["info"]["pubkey_node"]
    f = fetch.fetch_createcode(H_CR, "mainnet", transport=transport_from(rec), endpoints=MAIN)
    assert not f["ok"] and "ONE node" in f["reason"]
    f2 = fetch.fetch_createcode(H_CR, "mainnet", transport=transport_from(rec), endpoints=MAIN,
                                allow_single_operator=True)
    assert f2["ok"] and f2["distinct_operators"] == 1


@pytest.mark.parametrize("h,net,eps", [("XYZ", "mainnet", MAIN), (H_CR, "devnet", MAIN), (H_CR, "mainnet", MAIN[:1])])
def test_fetch_argument_errors(h, net, eps):
    f = fetch.fetch_createcode(h, net, transport=transport_from(recorded()), endpoints=eps)
    assert not f["ok"]


# ---------------- verify ----------------

def fake_builder(outputs):
    calls = []

    def b(src, recipe, params, preset, out_dir):
        o = outputs[len(calls)]
        calls.append(1)
        if isinstance(o, Exception):
            raise o
        return {"recipe": {"digest": "r" * 64}, "image": {"image_id": "sha256:x"},
                "source": {"tree_sha256": "t" * 64}, "params": {}}, o
    return b


def run_verify(outputs, rec=None, tmp=None, **kw):
    return V.verify(H_CR, FX, "xhc-bin127", "mainnet", transport=transport_from(rec or recorded()),
                    builder=fake_builder(outputs), endpoints=MAIN, out_dir=tmp, **kw)


def test_verify_reproduced(tmp_path):
    good = rd("claimreward_onledger.wasm")
    r = run_verify([good, good], tmp=str(tmp_path))
    assert r["verdict"] == "REPRODUCED" and V.EXIT[r["verdict"]] == 0
    assert (tmp_path / "onledger.wasm").read_bytes() == good
    assert json.loads((tmp_path / "verify-report.json").read_text())["verdict"] == "REPRODUCED"


def test_verify_one_byte_mismatch_with_section_diff():
    b = bytearray(rd("claimreward_onledger.wasm")); b[0x130] = 0x21
    r = run_verify([bytes(b), bytes(b)])
    assert r["verdict"] == "MISMATCH" and V.EXIT["MISMATCH"] == 2
    assert [s["section"] for s in r["diff"]["sections"] if s["status"] != "same"] == ["code"]
    assert [f["name"] for f in r["diff"]["functions"] if f["status"] != "same"] == ["hook"]


def test_verify_nondeterministic_build_unverified():
    good = rd("claimreward_onledger.wasm")
    r = run_verify([good, rd("claimreward_nearmiss_808.wasm")])
    assert r["verdict"] == "UNVERIFIED" and "NOT deterministic" in r["reason"]


def test_verify_build_failure_unverified():
    r = run_verify([BuildError("clang exploded"), None])
    assert r["verdict"] == "UNVERIFIED" and "rebuild 1 failed" in r["reason"]
    good = rd("claimreward_onledger.wasm")
    r2 = run_verify([good, RuntimeError("docker died")])
    assert r2["verdict"] == "UNVERIFIED" and "rebuild 2 failed" in r2["reason"]


def test_verify_read_failure_never_builds():
    rec = recorded(); rec[MAIN[1]] = fetch.RpcError("timeout")
    r = run_verify([AssertionError("builder must not run")] * 2, rec=rec)
    assert r["verdict"] == "UNVERIFIED" and "read failure" in r["reason"] and r["builds"] == []


def test_verify_disagreement_unverified_even_if_build_matches():
    rec = recorded()
    node = rec[MAIN[0]]["ledger_entry"]["result"]["node"]
    cc = bytearray.fromhex(node["CreateCode"]); cc[5] ^= 0xFF; node["CreateCode"] = cc.hex()
    good = rd("claimreward_onledger.wasm")
    r = run_verify([good, good], rec=rec)
    assert r["verdict"] == "UNVERIFIED" and "DISAGREE" in r["reason"]


def test_verify_single_operator_caveat():
    rec = recorded()
    rec[MAIN[1]]["server_info"]["result"]["info"]["pubkey_node"] = \
        rec[MAIN[0]]["server_info"]["result"]["info"]["pubkey_node"]
    good = rd("claimreward_onledger.wasm")
    assert run_verify([good, good], rec=rec)["verdict"] == "UNVERIFIED"
    r = run_verify([good, good], rec=rec, allow_single_operator=True)
    assert r["verdict"] == "REPRODUCED" and "single-operator" in r["caveat"]


def test_verify_source_changed_between_builds():
    good = rd("claimreward_onledger.wasm")
    calls = []

    def b(src, recipe, params, preset, out_dir):
        calls.append(1)
        return {"source": {"tree_sha256": str(len(calls)) * 64}}, good
    r = V.verify(H_CR, FX, transport=transport_from(recorded()), builder=b, endpoints=MAIN, network="mainnet")
    assert r["verdict"] == "UNVERIFIED" and "source tree changed" in r["reason"]


# ---------------- bind-review ----------------

def test_bind_review_covering(tmp_path):
    p = tmp_path / "review.md"
    p.write_text("Reviewed HookHash %s on mainnet.\n" % H_CR.lower())
    m, ok = bind.bind_review(str(p), H_CR, "xahau-mainnet", created_utc="2026-09-28T00:00:00Z")
    assert ok and m["coverage"] == "MENTIONS_HOOKHASH" and m["hookhash"] == H_CR
    # literal: shasum -a 256 of the exact bytes above
    import hashlib
    assert m["review"]["sha256"] == hashlib.sha256(p.read_bytes()).hexdigest()
    body = {k: v for k, v in m.items() if k not in ("signature", "canonical_sha256")}
    assert m["canonical_sha256"] == hashlib.sha256(bind.canonical(body)).hexdigest()


def test_bind_review_other_hash_only_fails(tmp_path):
    p = tmp_path / "review.md"
    p.write_text("Evidence covers wasm %s only.\n" % H_NEAR)
    m, ok = bind.bind_review(str(p), H_CR)
    assert not ok and m["coverage"] == "MENTIONS_OTHER_HASHES_ONLY" and H_NEAR in m["other_hashes_mentioned"]


def test_bind_review_prefix_only_and_absent(tmp_path):
    p = tmp_path / "r1.md"; p.write_text("hook 805351CE26FB… looked fine")
    m, ok = bind.bind_review(str(p), H_CR)
    assert not ok and m["coverage"] == "MENTIONS_HOOKHASH_PREFIX_ONLY"
    q = tmp_path / "r2.md"; q.write_text("no hashes here")
    m2, ok2 = bind.bind_review(str(q), H_CR)
    assert not ok2 and m2["coverage"] == "NOT_MENTIONED"


def test_bind_review_longer_hex_not_a_mention(tmp_path):
    p = tmp_path / "r.md"; p.write_text("blob " + H_CR + "AB")
    m, ok = bind.bind_review(str(p), H_CR)
    assert not ok


def test_bind_review_with_verify_report(tmp_path):
    p = tmp_path / "review.md"; p.write_text(H_CR)
    rep = tmp_path / "verify-report.json"
    rep.write_text(json.dumps({"verdict": "REPRODUCED", "hookhash": H_CR, "recipe": "xhc-bin127",
                               "builds": [{"recipe_digest": "d" * 64, "source_tree_sha256": "s" * 64}]}))
    m, ok = bind.bind_review(str(p), H_CR, verify_report=str(rep))
    assert ok and m["verify_report"]["verdict"] == "REPRODUCED"
    rep.write_text(json.dumps({"verdict": "MISMATCH", "hookhash": H_CR}))
    m, ok = bind.bind_review(str(p), H_CR, verify_report=str(rep))
    assert not ok and any("MISMATCH" in x for x in m["problems"])
    rep.write_text(json.dumps({"verdict": "REPRODUCED", "hookhash": H_NEAR}))
    m, ok = bind.bind_review(str(p), H_CR, verify_report=str(rep))
    assert not ok and any("different HookHash" in x for x in m["problems"])


def test_bind_review_bad_hash(tmp_path):
    p = tmp_path / "r.md"; p.write_text("x")
    with pytest.raises(ValueError):
        bind.bind_review(str(p), "1234")


# ---------------- recipes ----------------

def test_recipes_pinned_and_params_allowlisted():
    r = load_recipe("xhc-bin127")
    assert "@sha256:" in r["base_image"]
    assert resolve_params(r, preset="classic") == {"CLANG_OPT": "-O2", "WASMOPT": "-O2", "STAGES": "opt,clean"}
    with pytest.raises(BuildError):
        resolve_params(r, {"CLANG_OPT": "-O2; rm -rf /"})
    with pytest.raises(BuildError):
        resolve_params(r, {"NOPE": "x"})
    with pytest.raises(BuildError):
        resolve_params(r, preset="nope")
    k = load_recipe("kvt-llvm22")
    with pytest.raises(BuildError):
        resolve_params(k, {"ENTRY": "a.c b.c"})
    assert resolve_params(k, {"ENTRY": "hook_slot.c"})["ENTRY"] == "hook_slot.c"
    with pytest.raises(BuildError):
        load_recipe("../etc")


def test_recipe_digest_sensitive():
    r = load_recipe("xhc-bin127")
    d0 = recipe_digest(r)
    r2 = copy.deepcopy(r); r2["artifacts"][0]["sha256"] = "0" * 64
    assert recipe_digest(r2) != d0
    assert recipe_digest(load_recipe("xhc-bin127")) == d0


def test_validate_recipe_requires_pins():
    from hook_repro.build import validate_recipe
    good = {k: v for k, v in load_recipe("xhc-bin127").items() if k != "_dir"}
    validate_recipe(good)
    bad = copy.deepcopy(good); bad["base_image"] = "node:17-alpine"
    with pytest.raises(BuildError):
        validate_recipe(bad)
    bad = copy.deepcopy(good); bad["artifacts"][1]["sha256"] = "latest"
    with pytest.raises(BuildError):
        validate_recipe(bad)


def test_fetch_artifact_verifies_sha(tmp_path, monkeypatch):
    from hook_repro import build as B
    import hashlib
    monkeypatch.setattr(B, "CACHE", str(tmp_path / "cache"))
    src = tmp_path / "blob.bin"; src.write_bytes(b"pinned bytes")
    good = hashlib.sha256(b"pinned bytes").hexdigest()
    with pytest.raises(BuildError):
        B.fetch_artifact({"name": "blob", "url": src.as_uri(), "sha256": "0" * 64}, log=lambda *_: None)
    p = B.fetch_artifact({"name": "blob", "url": src.as_uri(), "sha256": good}, log=lambda *_: None)
    assert open(p, "rb").read() == b"pinned bytes"


def test_unpack_rejects_escaping_symlink(tmp_path):
    import io, tarfile
    from hook_repro import build as B
    tp = tmp_path / "a.tar"
    with tarfile.open(tp, "w") as t:
        ti = tarfile.TarInfo("pkg/bin/evil"); ti.type = tarfile.SYMTYPE; ti.linkname = "../../../etc/passwd"
        t.addfile(ti)
    with pytest.raises(BuildError):
        B.unpack_artifact({"name": "a", "unpack": "tar", "strip_prefix": "pkg/", "into": "x"}, str(tp), str(tmp_path / "ctx"))
    tp2 = tmp_path / "b.tar"
    with tarfile.open(tp2, "w") as t:
        data = b"#!/bin/sh\n"
        ti = tarfile.TarInfo("pkg/bin/clang-22"); ti.size = len(data); ti.mode = 0o755
        t.addfile(ti, io.BytesIO(data))
        ti = tarfile.TarInfo("pkg/bin/clang"); ti.type = tarfile.SYMTYPE; ti.linkname = "clang-22"
        t.addfile(ti)
        ti = tarfile.TarInfo("pkg/share/doc"); ti.size = 1
        t.addfile(ti, io.BytesIO(b"x"))
    B.unpack_artifact({"name": "b", "unpack": "tar", "strip_prefix": "pkg/", "include_prefix": ["pkg/bin/"], "into": "y"},
                      str(tp2), str(tmp_path / "ctx2"))
    y = tmp_path / "ctx2" / "y"
    assert os.readlink(y / "bin" / "clang") == "clang-22" and os.access(y / "bin" / "clang-22", os.X_OK)
    assert not (y / "share").exists()


def test_tree_hash_literal():
    # literal computed in the shell: for f in A.h a/z.h b.c hookapi.h; printf '%s\0%s\n' f sha256 | shasum -a 256
    h, listing = tree_hash(os.path.join(FX, "tree"))
    assert [e[0] for e in listing] == ["A.h", "a/z.h", "b.c", "hookapi.h"]
    assert h == "e72ce8ff02719def6b93b91bdc7e61653bcb7c24ccfea12a140c39c17c7b204c"


def test_fetch_odd_length_createcode_refused():
    rec = recorded()
    rec[MAIN[1]]["ledger_entry"]["result"]["node"]["CreateCode"] += "A"
    f = fetch.fetch_createcode(H_CR, "mainnet", transport=transport_from(rec), endpoints=MAIN)
    assert not f["ok"] and "not hex" in f["reason"]


def test_include_prefix_exact_vs_subtree():
    from hook_repro.build import _selected
    a = {"strip_prefix": "L/", "include_prefix": ["L/bin/clang", "L/lib/clang/22/include/"]}
    assert _selected("L/bin/clang", a) and not _selected("L/bin/clang-tidy", a)
    assert _selected("L/lib/clang/22/include/stdint.h", a) and not _selected("L/lib/libLLVM.so", a)


def test_deb_unpack(tmp_path):
    import io, tarfile
    from hook_repro import build as B
    tb = io.BytesIO()
    with tarfile.open(fileobj=tb, mode="w:gz") as t:
        data = b"ELF"
        ti = tarfile.TarInfo("./usr/lib/x/libfoo.so.1"); ti.size = 3; ti.mode = 0o644
        t.addfile(ti, io.BytesIO(data))
    payload = tb.getvalue()

    def member(name, body):
        hdr = name.ljust(16).encode() + "0".ljust(12).encode() + "0".ljust(6).encode() * 2 + \
            "100644".ljust(8).encode() + str(len(body)).ljust(10).encode() + b"`\n"
        return hdr + body + (b"\n" if len(body) % 2 else b"")
    deb = b"!<arch>\n" + member("debian-binary", b"2.0\n") + member("control.tar.gz", b"x") + member("data.tar.gz", payload)
    p = tmp_path / "foo.deb"; p.write_bytes(deb)
    B.unpack_artifact({"name": "foo", "unpack": "deb", "strip_prefix": "./usr/lib/x/", "into": "tc/lib"}, str(p), str(tmp_path / "ctx"))
    assert (tmp_path / "ctx" / "tc" / "lib" / "libfoo.so.1").read_bytes() == b"ELF"
    q = tmp_path / "bad.deb"; q.write_bytes(b"PK\x03\x04 not ar")
    with pytest.raises(BuildError):
        B.unpack_artifact({"name": "bad", "unpack": "deb", "into": "x"}, str(q), str(tmp_path / "ctx2"))

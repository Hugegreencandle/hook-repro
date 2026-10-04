"""Regression tests for the RT round-5 review of hookc / hook-repro.

Each test_rt5_* test is the fixed-behaviour form of one reviewer probe (each probe PASSED on
57a8efd while the bug existed, so each test_rt5_* test here FAILS on 57a8efd); test_guard_*
tests pin the fixes' edges. Docker is replaced by the round-1 FAKE CONTAINER and, for `verify`,
the chain read by the round-4 two-operator stub.

  P1  builder.cc / wasm_opt_version / commands / wasm_opt came from the FIRST twin's build log
      only; the other twin's log was never compared (build, reproduce, verify)
  P2  `verify --out` wrote verify-report.json before source_vcs was added: disk != --json stdout
  P3  the cargo vendor tree was trusted on a `.complete` marker in the same cache, keyed by a
      64-bit prefix of the lock digest
  P5  bind-review recorded no caveat for a --no-wce sidecar whose Fee/HookCallbackFee were not compared
"""
import json
import os

import pytest

from hook_repro import bind as BIND, build as B, cargo_lock, cli, hookc as HC

from test_rt_round1 import FAKE_LOG, FX, HOOK_C, container_view, fake, fake_wasm, load, mkrepo  # noqa: F401
from test_rt_round4 import chain_stub

# Another compiler, another command line and a wasm-opt stage that ran, with IDENTICAL output bytes.
OTHER_LOG = FAKE_LOG.replace("fake-clang 1", "OTHER-clang 99").replace("HOOKC_WASM_OPT_RAN=0", "HOOKC_WASM_OPT_RAN=1") \
    .replace("cc -o hook.wasm *.c", "cc -DEVIL -o hook.wasm *.c")


def twin_logs(monkeypatch, logs):
    """Fake container: identical bytes on every twin; the build log is logs[platform] (default FAKE_LOG)."""
    def run_container(recipe, image, src_dir, out_dir, params, timeout=None, vendor_dir=None):
        wasm = fake_wasm(container_view(src_dir), params)
        with open(os.path.join(out_dir, "hook.wasm"), "wb") as f:
            f.write(wasm)
        with open(os.path.join(out_dir, "build.txt"), "w") as f:
            f.write(logs.get(recipe["platform"], FAKE_LOG))
        return wasm
    monkeypatch.setattr(B, "run_container", run_container)


def build_both(tmp_path, monkeypatch, logs):
    twin_logs(monkeypatch, logs)
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    out = tmp_path / "o"
    rc = cli.main(["hookc", "build", "--git", str(r), "--toolchain", "hookc-llvm22", "--out", str(out)])
    return rc, r, out


def verify_json(monkeypatch, capsys, out, r, *extra):
    m = str(out / "0.hook.metadata.json")
    d = load(m)
    with open(out / "0.hook.wasm", "rb") as f:
        h = chain_stub(monkeypatch, f.read(), d["WCE"])
    capsys.readouterr()
    rc = cli.main(["verify", "--hookhash", h, "--metadata", m, "--git", str(r), "--json"] + list(extra))
    return rc, json.loads(capsys.readouterr().out)


def reproduce_json(capsys, out, r, *extra):
    capsys.readouterr()
    rc = cli.main(["hookc", "reproduce", "--metadata", str(out / "0.hook.metadata.json"), "--git", str(r),
                   "--json"] + list(extra))
    return rc, json.loads(capsys.readouterr().out)


# ---------------- P1: every twin's build log must agree with the sidecar ----------------

def test_rt5_p1_build_refuses_twins_whose_logs_disagree(fake, tmp_path, monkeypatch):
    # the reviewer's probe: the amd64 twin's log states another compiler, command line and wasm-opt stage
    rc, r, out = build_both(tmp_path, monkeypatch, {"linux/amd64": OTHER_LOG})
    assert rc == 3
    assert not os.path.exists(out / "0.hook.metadata.json")


def test_rt5_p1_build_refuses_when_only_the_second_twin_differs(fake, tmp_path, monkeypatch, capsys):
    rc, r, out = build_both(tmp_path, monkeypatch, {"linux/arm64": OTHER_LOG})
    assert rc == 3
    assert "TWIN BUILD LOGS DISAGREE" in capsys.readouterr().err
    assert not os.path.exists(out / "0.hook.metadata.json")


def test_rt5_p1_verify_mismatch_when_second_twin_log_differs(fake, tmp_path, monkeypatch, capsys):
    logs = {}
    rc, r, out = build_both(tmp_path, monkeypatch, logs)
    assert rc == 0
    logs["linux/arm64"] = OTHER_LOG  # at verify time the second twin's log states another toolchain
    rc, rep = verify_json(monkeypatch, capsys, out, r)
    assert rc == 2 and rep["verdict"] == "MISMATCH"
    assert "linux/arm64" in rep["reason"] and "builder.cc" in rep["metadata_diff"]


def test_rt5_p1_reproduce_mismatch_when_second_twin_log_differs(fake, tmp_path, monkeypatch, capsys):
    logs = {}
    rc, r, out = build_both(tmp_path, monkeypatch, logs)
    assert rc == 0
    logs["linux/arm64"] = OTHER_LOG
    rc, rep = reproduce_json(capsys, out, r)
    assert rc == 2 and rep["verdict"] == "MISMATCH"
    assert "linux/arm64" in rep["reason"]
    assert {"builder.cc", "builder.commands", "builder.wasm_opt"} <= set(rep["metadata_diff"])


@pytest.mark.parametrize("field,log", [
    ("wasm_opt", FAKE_LOG.replace("HOOKC_WASM_OPT_RAN=0", "HOOKC_WASM_OPT_RAN=1")),
    ("commands", FAKE_LOG.replace("cc -o hook.wasm *.c", "cc -DEVIL -o hook.wasm *.c")),
    ("cc", FAKE_LOG.replace("fake-clang 1", "fake-clang 2")),
    ("wasm_opt_version", FAKE_LOG.replace("fake-opt 1", "fake-opt 2")),
])
def test_rt5_p1_each_log_field_compared_across_twins(fake, tmp_path, monkeypatch, capsys, field, log):
    logs = {}
    rc, r, out = build_both(tmp_path, monkeypatch, logs)
    assert rc == 0
    logs["linux/arm64"] = log
    rc, rep = reproduce_json(capsys, out, r)
    assert rc == 2 and rep["metadata_diff"] == ["builder." + field]
    rc, rep = verify_json(monkeypatch, capsys, out, r)
    assert rc == 2 and rep["metadata_diff"] == ["builder." + field]


def test_guard_p1_honest_equal_twins_reproduce_and_verify(fake, tmp_path, monkeypatch, capsys):
    rc, r, out = build_both(tmp_path, monkeypatch, {})
    assert rc == 0
    assert load(out / "0.hook.metadata.json")["builder"]["platforms_built"] == ["linux/amd64", "linux/arm64"]
    rc, rep = reproduce_json(capsys, out, r)
    assert rc == 0 and rep["verdict"] == "REPRODUCED" and rep["platforms_built_rechecked"] is True
    rc, rep = verify_json(monkeypatch, capsys, out, r)
    assert rc == 0 and rep["verdict"] == "REPRODUCED" and rep["platforms_built_rechecked"] is True
    assert rep["platforms_rebuilt"] == ["linux/amd64", "linux/arm64"]


def test_guard_p1_single_twin_run_compares_that_twins_log(fake, tmp_path, monkeypatch, capsys):
    logs = {}
    rc, r, out = build_both(tmp_path, monkeypatch, logs)
    assert rc == 0
    logs["linux/arm64"] = OTHER_LOG
    assert reproduce_json(capsys, out, r, "--platform", "linux/arm64")[0] == 2
    assert reproduce_json(capsys, out, r, "--platform", "linux/amd64")[0] == 0


def test_guard_p1_twin_log_disagreement_unit():
    assert HC.twin_log_disagreement([("linux/amd64", FAKE_LOG), ("linux/arm64", FAKE_LOG)]) is None
    why = HC.twin_log_disagreement([("linux/amd64", FAKE_LOG), ("linux/arm64", OTHER_LOG)])
    assert why and "linux/arm64" in why and "cc/commands/wasm_opt" in why
    with pytest.raises(HC.HookcError, match="HOOKC_WASM_OPT_RAN"):
        HC.twin_log_disagreement([("linux/amd64", FAKE_LOG), ("linux/arm64", "clang_version: x\n")])


def test_guard_p1_recorded_llvm22_twins_agree():
    """The published claimreward-llvm22 build (both twins, real containers) has equal log fields, so the
    cross-twin check keeps that evidence REPRODUCED."""
    base = os.path.join(FX, "..", "..", "casestudy", "hookc", "claimreward-llvm22", "builds")
    logs = []
    for plat in ("linux-amd64", "linux-arm64"):
        for n in (1, 2):
            with open(os.path.join(base, plat, "build%d" % n, "build-manifest.json")) as f:
                logs.append((plat, json.load(f)["container_log"]))
    assert HC.twin_log_disagreement(logs) is None
    with open(os.path.join(base, "..", "0.hook.metadata.json")) as f:
        b = json.load(f)["builder"]
    assert {k: b[k] for k in HC.LOG_FIELDS} == HC.log_fields(logs[-1][1])


# ---------------- P2: verify-report.json on disk carries source_vcs ----------------

def test_rt5_p2_report_on_disk_has_source_vcs(fake, tmp_path, monkeypatch, capsys):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    out = tmp_path / "o"
    assert cli.main(["hookc", "build", "--git", str(r), "--toolchain", "hookc-llvm22", "--platform", "linux/arm64",
                     "--out", str(out)]) == 0
    vout = tmp_path / "v"
    rc, stdout = verify_json(monkeypatch, capsys, out, r, "--platform", "linux/arm64", "--out", str(vout))
    disk = load(vout / "verify-report.json")
    assert rc == 0 and stdout["verdict"] == "REPRODUCED"
    assert disk["source_vcs"] == stdout["source_vcs"]
    assert disk["source_vcs"]["commit"] == load(out / "0.hook.metadata.json")["source"]["vcs"]["commit"]


def test_guard_p2_failed_verify_report_on_disk_has_source_vcs(fake, tmp_path, monkeypatch, capsys):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    out = tmp_path / "o"
    assert cli.main(["hookc", "build", "--git", str(r), "--toolchain", "hookc-llvm22", "--platform", "linux/arm64",
                     "--out", str(out)]) == 0
    chain_stub(monkeypatch, b"\0asm\1\0\0\0", {})  # chain serves other bytes for another hash
    m = str(out / "0.hook.metadata.json")
    vout = tmp_path / "v"
    capsys.readouterr()
    rc = cli.main(["verify", "--hookhash", load(m)["HookHash"], "--metadata", m, "--git", str(r), "--platform",
                   "linux/arm64", "--out", str(vout), "--json"])
    stdout = json.loads(capsys.readouterr().out)
    disk = load(vout / "verify-report.json")
    assert rc == 3 and disk == stdout and "source_vcs" in disk


# ---------------- P3: vendor tree re-derived, never trusted from the cache ----------------

LOCK = ('version = 3\n[[package]]\nname = "serde"\nversion = "1.0.0"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        'checksum = "%s"\n' % ("ab" * 32))


def vendor_setup(tmp_path, monkeypatch):
    monkeypatch.setattr(B, "CACHE", str(tmp_path / "cache"))
    src = tmp_path / "src"
    src.mkdir()
    (src / "Cargo.lock").write_text(LOCK)
    digest = cargo_lock.lock_digest(cargo_lock.parse_lock(str(src / "Cargo.lock")))
    fetched = []

    def fetch(a, log=print):
        fetched.append(a["sha256"])
        return "verified.crate"

    def unpack(a, path, root):
        d = os.path.join(root, "vendor", "serde-1.0.0")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "lib.rs"), "w") as f:
            f.write("// GENUINE\n")
    monkeypatch.setattr(B, "fetch_artifact", fetch)
    monkeypatch.setattr(B, "unpack_artifact", unpack)
    return src, digest, fetched


def plant(root):
    os.makedirs(os.path.join(root, "vendor", "serde-1.0.0"), exist_ok=True)
    with open(os.path.join(root, "vendor", "serde-1.0.0", "lib.rs"), "w") as f:
        f.write("// PLANTED\n")
    with open(os.path.join(root, ".complete"), "w") as f:
        f.write(B.content_digest(os.path.join(root, "vendor")))


def planted_run(tmp_path, monkeypatch, key):
    src, digest, fetched = vendor_setup(tmp_path, monkeypatch)
    plant(os.path.join(str(tmp_path / "cache"), "vendor", key(digest)))
    vdir, info = B.prepare_source_vendor(str(src), {"LOCK": "Cargo.lock"}, log=lambda *_: None)
    return digest, fetched, vdir, info


def test_rt5_p3_planted_vendor_tree_with_complete_marker_not_used(tmp_path, monkeypatch):
    # the reviewer's probe: a tree + self-consistent .complete planted at the 64-bit-prefix key
    digest, fetched, vdir, info = planted_run(tmp_path, monkeypatch, lambda d: d[:16])
    assert fetched == ["ab" * 32]  # re-derived from the sha256-pinned crate
    with open(os.path.join(vdir, "serde-1.0.0", "lib.rs")) as f:
        assert f.read() == "// GENUINE\n"
    assert info["vendor_digest"] == digest


def test_guard_p3_planted_at_full_digest_key_not_used(tmp_path, monkeypatch):
    digest, fetched, vdir, info = planted_run(tmp_path, monkeypatch, lambda d: d)
    assert fetched == ["ab" * 32]  # re-derived from the sha256-pinned crate
    with open(os.path.join(vdir, "serde-1.0.0", "lib.rs")) as f:
        assert f.read() == "// GENUINE\n"
    assert info["vendor_digest"] == digest


def test_guard_p3_vendor_tree_keyed_by_full_lock_digest(tmp_path, monkeypatch):
    src, digest, _ = vendor_setup(tmp_path, monkeypatch)
    vdir, _ = B.prepare_source_vendor(str(src), {"LOCK": "Cargo.lock"}, log=lambda *_: None)
    assert vdir == os.path.join(str(tmp_path / "cache"), "vendor", digest, "vendor") and len(digest) == 64


# ---------------- P5: bind-review caveat for a --no-wce sidecar ----------------

def no_wce_verify(fake, tmp_path, monkeypatch, capsys, no_wce=True):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    out = tmp_path / "o"
    assert cli.main(["hookc", "build", "--git", str(r), "--toolchain", "hookc-llvm22", "--platform", "linux/arm64",
                     "--out", str(out)] + (["--no-wce"] if no_wce else [])) == 0
    m = str(out / "0.hook.metadata.json")
    d = load(m)
    with open(out / "0.hook.wasm", "rb") as f:
        h = chain_stub(monkeypatch, f.read(), d["WCE"] if not no_wce else {"hook": 999999, "cbak": 5})
    vout = tmp_path / "v"
    rc = cli.main(["verify", "--hookhash", h, "--metadata", m, "--git", str(r), "--out", str(vout)])
    review = tmp_path / "review.md"
    review.write_text("Review of hook %s\n" % h)
    capsys.readouterr()
    brc = cli.main(["bind-review", str(review), "--hookhash", h, "--verify-report", str(vout / "verify-report.json")])
    return rc, load(vout / "verify-report.json"), brc, json.loads(capsys.readouterr().out)


def test_rt5_p5_bind_records_wce_not_compared_caveat(fake, tmp_path, monkeypatch, capsys):
    rc, rep, brc, bm = no_wce_verify(fake, tmp_path, monkeypatch, capsys)
    assert rc == 0 and rep["verdict"] == "REPRODUCED" and "not compared" in rep["reason"]
    assert brc == 0 and bm["problems"] == []
    assert [c for c in bm["caveats"] if "Fee/HookCallbackFee NOT compared" in c and "WCE is null" in c]


def test_guard_p5_wce_sidecar_has_no_wce_caveat(fake, tmp_path, monkeypatch, capsys):
    rc, rep, brc, bm = no_wce_verify(fake, tmp_path, monkeypatch, capsys, no_wce=False)
    assert rc == 0 and brc == 0 and bm["caveats"] == []


def test_guard_p5_report_caveats_unit():
    row = {"definition": "Fee", "enforced": True, "match": None}
    assert any("Fee NOT compared" in c for c in BIND.report_caveats(
        {"distinct_operators": 2, "definition_check": {"fields": [row]}}))
    assert any("NOT compared" in c for c in BIND.report_caveats(
        {"distinct_operators": 2, "metadata": {"doc": {"WCE": {"hook": None, "cbak": None}}}}))
    informational = dict(row, definition="HookOn", enforced=False)
    assert BIND.report_caveats({"distinct_operators": 2, "definition_check": {"fields": [informational]},
                                "metadata": {"doc": {"WCE": {"hook": 1, "cbak": 0}}}}) == []


# ---------------- P1 follow-up: a twin whose BYTES differ is named by the byte check ----------------
# With the sidecar regenerated from every twin (P1), a twin that builds other bytes would ALSO fail
# the sidecar comparison (its HookHash differs). That must not become the reported reason: the
# report has to say the bytes differ (and, in verify, attach the diff), never "bytes reproduce" /
# "bytes match the chain". These tests kill mutants "rt2 N6" and "rt3 R3-05".

def second_twin_bytes_differ(fake, tmp_path, monkeypatch):
    rc, r, out = build_both(tmp_path, monkeypatch, {})
    assert rc == 0
    real = B.run_container

    def per_arch(recipe, image, src_dir, out_dir, params, timeout=None, vendor_dir=None):
        w = real(recipe, image, src_dir, out_dir, params, timeout, vendor_dir)
        if recipe["platform"] == "linux/arm64":  # the second twin now builds other bytes
            w = w + bytes([0, 2, 1, 0x61])
            with open(os.path.join(out_dir, "hook.wasm"), "wb") as f:
                f.write(w)
        return w
    monkeypatch.setattr(B, "run_container", per_arch)
    return r, out


def test_guard_p1_reproduce_names_second_twin_bytes_not_sidecar(fake, tmp_path, monkeypatch, capsys):
    r, out = second_twin_bytes_differ(fake, tmp_path, monkeypatch)
    rc, rep = reproduce_json(capsys, out, r)
    assert rc == 2 and rep["verdict"] == "MISMATCH"
    assert rep["reason"].startswith("rebuilt HookHash ") and "(linux/arm64) != metadata HookHash" in rep["reason"]
    assert "bytes reproduce" not in rep["reason"] and rep["metadata_diff"] == []


def test_guard_p1_verify_names_second_twin_chain_difference_not_sidecar(fake, tmp_path, monkeypatch, capsys):
    r, out = second_twin_bytes_differ(fake, tmp_path, monkeypatch)
    rc, rep = verify_json(monkeypatch, capsys, out, r)
    assert rc == 2 and rep["verdict"] == "MISMATCH"
    assert "differs from on-ledger" in rep["reason"] and "(linux/arm64 twin)" in rep["reason"]
    assert "bytes match the chain" not in rep["reason"] and rep["diff"] is not None
    assert "metadata_diff" not in rep


def test_guard_p1_verify_names_the_nondeterministic_twin(fake, tmp_path, monkeypatch, capsys):
    """Fast, early kill for mutant "rt3 R3-03: failing twin not named" (its round-3 killer runs late in
    the suite and timed out under a loaded full mutation run)."""
    rc, r, out = build_both(tmp_path, monkeypatch, {})
    assert rc == 0
    real, n = B.run_container, {"arm": 0}

    def flaky_arm(recipe, image, src_dir, out_dir, params, timeout=None, vendor_dir=None):
        w = real(recipe, image, src_dir, out_dir, params, timeout, vendor_dir)
        if recipe["platform"] == "linux/arm64":
            n["arm"] += 1
            if n["arm"] == 2:  # the second arm64 build differs from the first
                w = w + bytes([0, 2, 1, 0x61])
                with open(os.path.join(out_dir, "hook.wasm"), "wb") as f:
                    f.write(w)
        return w
    monkeypatch.setattr(B, "run_container", flaky_arm)
    rc, rep = verify_json(monkeypatch, capsys, out, r)
    assert rc == 3 and rep["verdict"] == "UNVERIFIED"
    assert "rebuild on linux/arm64 is NOT deterministic" in rep["reason"]

"""Build manifests and verify reports are published as evidence, so they must not record the build
host's absolute paths (user name, home layout). build.portable_path writes a path under the
hook-repro cache as "$HOOK_REPRO_CACHE/...", one under the current directory relative to it, one
under the home directory as "~/...". Expectations are literals.
"""
import json
import os

from hook_repro import build as B

from test_rt_round1 import HOOK_C, hookc, mkrepo  # noqa: F401
from test_rt_round3 import ARM, TC_ARM, sim, stub_chain, verify  # noqa: F401


def test_portable_path_literals(tmp_path, monkeypatch):
    home, cache, cwd = tmp_path / "home", tmp_path / "home" / ".cache" / "hook-repro", tmp_path / "work"
    for d in (cache, cwd):
        d.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(B, "CACHE", str(cache))
    monkeypatch.chdir(cwd)
    assert B.portable_path(str(cache / "tmp" / "hookc-src-x" / "src")) == "$HOOK_REPRO_CACHE/tmp/hookc-src-x/src"
    assert B.portable_path(str(cache)) == "$HOOK_REPRO_CACHE"
    assert B.portable_path(str(cwd / "out" / "build1" / "hook.wasm")) == os.path.join("out", "build1", "hook.wasm")
    assert B.portable_path("out/build1/hook.wasm") == os.path.join("out", "build1", "hook.wasm")
    assert B.portable_path(str(home / "src" / "repo")) == "~/src/repo"
    assert B.portable_path(str(home)) == "~"
    assert B.portable_path("/opt/elsewhere/x") == "/opt/elsewhere/x"        # outside all three: as given
    assert B.portable_path(str(tmp_path / "homework")) == str(tmp_path / "homework")  # prefix, not a parent


def _strings(o):
    if isinstance(o, dict):
        for v in o.values():
            yield from _strings(v)
    elif isinstance(o, list):
        for v in o:
            yield from _strings(v)
    elif isinstance(o, str):
        yield o


def test_manifests_and_verify_report_carry_no_absolute_host_path(sim, tmp_path, monkeypatch):
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    r = mkrepo(tmp_path / "repo", {"hook/hook.c": HOOK_C})
    assert hookc("build", "--git", r, "--path", "hook", *TC_ARM, "--out", "o") == 0
    m = os.path.join("o", "0.hook.metadata.json")
    h = stub_chain(monkeypatch, (work / "o" / "0.hook.wasm").read_bytes())
    assert verify(h, m, "--git", r, "--out", "v", *ARM) == 0
    docs = [json.load(open(os.path.join(dp, f))) for dp, _, fs in os.walk(work) for f in fs
            if f in ("build-manifest.json", "verify-report.json")]
    assert len(docs) >= 3  # 2 build manifests + 2 rebuild manifests + the report
    leaked = [s for d in docs for s in _strings(d) if str(tmp_path) in s]
    assert leaked == []
    rep = json.load(open(work / "v" / "verify-report.json"))
    assert rep["source_dir"].startswith("$HOOK_REPRO_CACHE/")
    man = [d for d in docs if "output" in d][0]
    assert not os.path.isabs(man["output"]["file"]) and man["source"]["dir"].startswith("$HOOK_REPRO_CACHE/")

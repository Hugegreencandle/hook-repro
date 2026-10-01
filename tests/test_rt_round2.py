"""Regression tests for the 2026-09-29 hostile red-team of hookc / hook-repro (round 2).

Each test is the offline form of one RT round-2 repro script (scratchpad/rt2/n*.sh|py), with
docker replaced by the round-1 FAKE CONTAINER (it "compiles" exactly the directory it is
handed, so anything the container receives changes the output bytes). Expectations are
literals (exit codes 0/2/3, verdict strings). Every test named test_rt2_* fails on ec8eaeb.

  N1  git replace refs / mirror clones / GIT_* env steer the export to other objects
  N2  a committed file name becomes compiler flags (unquoted $SOURCES)
  N3  .gitattributes ident/filter/eol make the reviewed checkout differ from the blob built
  N4  HookDefinition.HookOn is the first installer's, not the build's; reason overclaims
  N5  the compiler sees the host kernel (/sys, /proc)
  N6  the sidecar lists every twin whether or not it was built
  N7  a container timeout is a traceback (exit 1) and leaves the container running
"""
import os
import subprocess

import pytest

from hook_repro import build as B, cli, hookc as HC, verify as V
from hook_repro.hashing import sha512half

from test_rt_round1 import (FX, HOOK_C, TC, fake, git, gtxt, hookc, load, mkrepo, rd,  # noqa: F401
                            save)

ARM = ["--platform", "linux/arm64"]


def fresh_dir():
    """run_container refuses a non-empty out dir since RT round 3 (R3-04)."""
    import tempfile
    return tempfile.mkdtemp(prefix="rt2-out-")


def built(fake, tmp_path, files, *extra):
    r = mkrepo(tmp_path / "repo", files)
    assert hookc("build", "--git", r, *TC, *extra, "--out", tmp_path / "o") == 0
    return r, str(tmp_path / "o" / "0.hook.metadata.json")


# ---------------- N7: timeouts are UNVERIFIED and kill the container ----------------

def test_rt2_n7_container_timeout_is_unverified_not_a_traceback(fake, tmp_path, monkeypatch):
    r, m = built(fake, tmp_path, {"hook.c": HOOK_C})

    def slow(*a, **k):
        raise subprocess.TimeoutExpired(["docker", "run"], 900)
    monkeypatch.setattr(B, "run_container", slow)
    assert hookc("reproduce", "--metadata", m, "--git", r, *ARM) == 3
    assert hookc("build", "--git", r, *TC, "--out", tmp_path / "o2") == 3


def test_rt2_n7_timed_out_container_is_killed_by_name(monkeypatch):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if cmd[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))
        return subprocess.CompletedProcess(cmd, 0, "", "")
    monkeypatch.setattr(subprocess, "run", fake_run)
    r = B.load_recipe("hookc-llvm22")
    with pytest.raises(B.BuildError, match="timeout"):
        B.run_container(r, {"image_id": "sha256:x"}, FX, fresh_dir(), {}, timeout=1)
    run = calls[0]
    name = run[run.index("--name") + 1]
    assert name.startswith("hook-repro-hookc-llvm22-")
    assert ["docker", "kill", name] in calls


def test_rt2_n7_interrupted_container_is_killed(monkeypatch):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if cmd[:2] == ["docker", "run"]:
            raise KeyboardInterrupt
        return subprocess.CompletedProcess(cmd, 0, "", "")
    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(KeyboardInterrupt):
        B.run_container(B.load_recipe("kvt-llvm22"), {"image_id": "sha256:x"}, FX, fresh_dir(), {})
    name = calls[0][calls[0].index("--name") + 1]
    assert ["docker", "kill", name] in calls


def test_guard_n7_finished_container_is_not_killed(monkeypatch, tmp_path):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if cmd[:2] == ["docker", "run"]:
            (tmp_path / "hook.wasm").write_bytes(b"\0asm")
        return subprocess.CompletedProcess(cmd, 0, "", "")
    monkeypatch.setattr(subprocess, "run", fake_run)
    assert B.run_container(B.load_recipe("kvt-llvm22"), {"image_id": "sha256:x"}, FX, str(tmp_path), {}) == b"\0asm"
    assert [c for c in calls if c[:2] == ["docker", "kill"]] == []


def test_guard_n7_wce_timeout_is_null_with_reason(monkeypatch, tmp_path):
    monkeypatch.setattr(B, "CACHE", str(tmp_path))
    monkeypatch.setattr(B, "ensure_image", lambda r, log=None: {"image_id": "sha256:x"})
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        if cmd[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(cmd, 300)
        return subprocess.CompletedProcess(cmd, 0, "", "")
    monkeypatch.setattr(subprocess, "run", fake_run)
    wce, why = HC.run_wce(rd("tiny.wasm"))
    assert wce is None and "timeout" in why
    assert any(c[:2] == ["docker", "kill"] for c in calls)


# ---------------- N4: HookDefinition.HookOn is informational; reason names compared rows ----------------

CODE = rd("tiny.wasm")
H_TINY = sha512half(CODE)
DECL_ON = "F" * 63 + "E"


def def_transport(defn):
    def t(url, payload):
        if payload["method"] == "server_info":
            return {"result": {"status": "success", "info": {"pubkey_node": "n9" + url[-6:], "network_id": 21337}}}
        node = {"LedgerEntryType": "HookDefinition", "HookHash": H_TINY, "CreateCode": CODE.hex().upper(),
                "Fee": "20"} | defn  # WCE.cbak 0: SetHook writes no HookCallbackFee (RT3 R3-09)
        return {"result": {"status": "success", "validated": True, "ledger_index": 100, "ledger_hash": "AB" * 32,
                           "node": node}}
    return t


def n4_verify(defn, doc=None):
    builder = lambda src, r, p, pr, o: ({"recipe": {"digest": "d"}, "image": {"image_id": "i"},  # noqa: E731
                                         "source": {"tree_sha256": "t"}, "params": {}}, CODE)
    meta = {"hookhash": H_TINY, "doc": doc or {"WCE": {"hook": 20, "cbak": 0}, "HookOn": DECL_ON, "HookCanEmit": None}}
    return V.verify(H_TINY, ".", "hookc-llvm22", transport=def_transport(defn), builder=builder, metadata=meta,
                    sidecar=lambda w, m, b=None: (True, None, []))


def test_rt2_n4a_first_installer_hookon_is_not_a_mismatch():
    rep = n4_verify({"HookOn": "0" * 64})  # honest bytes + sidecar; the first installer chose another HookOn
    assert rep["verdict"] == "REPRODUCED" and V.EXIT[rep["verdict"]] == 0
    rows = {r["definition"]: (r["match"], r["enforced"]) for r in rep["definition_check"]["fields"]}
    assert rows["HookOn"] == (False, False)
    assert "HookOn differs" in rep["reason"] and "Fee/HookCallbackFee (absent, WCE.cbak 0) equal" in rep["reason"]


def test_rt2_n4b_hookonv2_definition_reason_does_not_claim_hookon():
    rep = n4_verify({"HookOnIncoming": "0" * 64, "HookOnOutgoing": "F" * 64})
    assert rep["verdict"] == "REPRODUCED"
    assert "HookOn agree" not in rep["reason"] and "HookOn equal" not in rep["reason"]
    assert "HookOn not compared" in rep["reason"]


def test_rt2_n4_reason_never_names_uncompared_enforced_rows():
    rep = n4_verify({"HookOn": DECL_ON}, doc={"WCE": {"hook": None, "cbak": None}, "HookOn": DECL_ON,
                                               "HookCanEmit": None})
    assert rep["verdict"] == "REPRODUCED"
    assert "no enforced HookDefinition field was compared" in rep["reason"]
    assert "Fee/HookCallbackFee not compared" in rep["reason"]
    assert "HookOn equal" in rep["reason"]


def test_guard_n4_fee_disagreement_still_mismatch():
    rep = n4_verify({"HookOn": DECL_ON, "Fee": "21"})
    assert rep["verdict"] == "MISMATCH" and "Fee 21 != WCE.hook 20" in rep["reason"]


# ---------------- N1: replace refs / mirror clones / GIT_* env / alternates / grafts ----------------

GENUINE_C = b'#include "hookapi.h"\nint64_t hook(uint32_t r) { _g(1,1); return accept(0, 0, 10); }\n'
EVIL_C = GENUINE_C.replace(b"accept(0, 0, 10)", b"accept(0, 0, 1000000)")


def blob_w(r, data):
    return git(r, "hash-object", "-w", "--stdin", input=data).decode().strip()


def replaced_repo(fake, tmp_path):
    """n1_replace_objects_e2e.sh: genuine commit C / tree T; refs/replace/T -> tree of EVIL_C.
    Returns (repo, C, T, T2, evil sidecar naming C/T whose bytes and tree_sha256 are EVIL_C's,
    which is exactly what ec8eaeb's `hookc build --git repo` wrote)."""
    r = mkrepo(tmp_path / "repo", {"hook.c": GENUINE_C})
    c, t = gtxt(r, "rev-parse", "HEAD"), gtxt(r, "rev-parse", "HEAD^{tree}")
    t2 = git(r, "mktree", input=b"100644 blob %s\thook.c\n" % blob_w(r, EVIL_C).encode()).decode().strip()
    git(r, "replace", t, t2)
    e = mkrepo(tmp_path / "evil", {"hook.c": EVIL_C})
    assert hookc("build", "--git", e, *TC, "--out", tmp_path / "eo") == 0
    d = load(tmp_path / "eo" / "0.hook.metadata.json")
    d["source"]["vcs"].update(commit=c, tree=t)
    return r, c, t, t2, save(tmp_path / "evil.json", d)


def honest_hash(fake, tmp_path, data):
    h = mkrepo(tmp_path / "honest", {"hook.c": data})
    assert hookc("build", "--git", h, *TC, "--out", tmp_path / "ho") == 0
    return load(tmp_path / "ho" / "0.hook.metadata.json")["HookHash"]


def test_rt2_n1_build_compiles_the_genuine_tree_not_the_replacement(fake, tmp_path):
    r, c, t, t2, _ = replaced_repo(fake, tmp_path)
    assert hookc("build", "--git", r, "--rev", c, *TC, "--out", tmp_path / "o") == 0
    d = load(tmp_path / "o" / "0.hook.metadata.json")
    assert d["source"]["vcs"]["tree"] == t
    assert d["HookHash"] == honest_hash(fake, tmp_path, GENUINE_C)


def test_rt2_n1_replace_ref_in_repo_is_never_reproduced(fake, tmp_path):
    r, c, t, t2, m = replaced_repo(fake, tmp_path)
    assert hookc("reproduce", "--metadata", m, "--src", r, *ARM) in (2, 3)
    assert hookc("reproduce", "--metadata", m, "--git", r, *ARM) in (2, 3)


def test_rt2_n1_mirror_clone_carrying_replace_refs_is_never_reproduced(fake, tmp_path):
    r, c, t, t2, m = replaced_repo(fake, tmp_path)
    git(tmp_path, "clone", "-q", "--mirror", str(r), str(tmp_path / "mirror.git"))
    assert gtxt(tmp_path / "mirror.git", "for-each-ref", "refs/replace", "--format=%(refname)") == "refs/replace/" + t
    assert hookc("reproduce", "--metadata", m, "--git", tmp_path / "mirror.git", *ARM) in (2, 3)


def test_rt2_n1_git_dir_env_pointing_at_a_replacing_repo_is_ignored(fake, tmp_path, monkeypatch):
    r, c, t, t2, m = replaced_repo(fake, tmp_path)
    git(tmp_path, "clone", "-q", str(r), str(tmp_path / "clean"))
    monkeypatch.setenv("GIT_DIR", str(r / ".git"))
    assert hookc("reproduce", "--metadata", m, "--git", tmp_path / "clean", *ARM) in (2, 3)


def test_rt2_n1_replace_ref_base_env_is_ignored(fake, tmp_path, monkeypatch):
    r, c, t, t2, m = replaced_repo(fake, tmp_path)
    git(r, "replace", "-d", t)
    git(r, "update-ref", "refs/evil/" + t, t2)  # a replace ref under a custom base
    monkeypatch.setenv("GIT_REPLACE_REF_BASE", "refs/evil/")
    assert hookc("reproduce", "--metadata", m, "--git", r, *ARM) in (2, 3)


def test_rt2_n1_global_config_env_cannot_turn_replacement_back_on(fake, tmp_path, monkeypatch):
    r, c, t, t2, m = replaced_repo(fake, tmp_path)
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.useReplaceRefs")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "true")
    assert hookc("reproduce", "--metadata", m, "--git", r, *ARM) in (2, 3)


def test_rt2_n1_alternates_refused(fake, tmp_path):
    r = mkrepo(tmp_path / "repo", {"hook.c": GENUINE_C})
    git(tmp_path, "clone", "-q", "--shared", str(r), str(tmp_path / "shared"))
    assert os.path.exists(tmp_path / "shared" / ".git" / "objects" / "info" / "alternates")
    assert hookc("build", "--git", tmp_path / "shared", *TC, "--out", tmp_path / "o") == 3


def test_rt2_n1_grafts_refused(fake, tmp_path):
    r = mkrepo(tmp_path / "repo", {"hook.c": GENUINE_C})
    (r / ".git" / "info").mkdir(exist_ok=True)
    (r / ".git" / "info" / "grafts").write_text(gtxt(r, "rev-parse", "HEAD") + "\n")
    assert hookc("build", "--git", r, *TC, "--out", tmp_path / "o") == 3


def test_guard_n1_git_env_is_scrubbed(monkeypatch):
    for k in ("GIT_DIR", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG_PARAMETERS",
              "GIT_CEILING_DIRECTORIES", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
        monkeypatch.setenv(k, "/evil")
    monkeypatch.setenv("XDG_CONFIG_HOME", "/evil")
    env = HC.git_env()
    assert not [k for k in env if k.startswith("GIT_") and k not in (
        "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_ATTR_NOSYSTEM", "GIT_NO_REPLACE_OBJECTS",
        "GIT_TERMINAL_PROMPT", "GIT_OPTIONAL_LOCKS", "GIT_LITERAL_PATHSPECS")]
    assert env["GIT_NO_REPLACE_OBJECTS"] == "1" and env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["HOME"] == env["XDG_CONFIG_HOME"] != "/evil" and os.listdir(env["HOME"]) == []
    assert HC.git_cmd("r", "x")[:2] == ["git", "--no-replace-objects"]


def test_guard_n1_planted_tree_object_refused(fake, tmp_path):
    # n1b_planted_tree_object.sh: loose object file of tree T overwritten with another tree
    r = mkrepo(tmp_path / "repo", {"hook.h": b"int x = 1;\n"})
    t = gtxt(r, "rev-parse", "HEAD^{tree}")
    t2 = git(r, "mktree", input=b"100644 blob %s\thook.h\n" % blob_w(r, b"int x = 666;\n").encode()).decode().strip()
    f, f2 = (r / ".git" / "objects" / x[:2] / x[2:] for x in (t, t2))
    os.chmod(f, 0o644)
    f.write_bytes(f2.read_bytes())
    with pytest.raises(HC.HookcError, match="does not hash to its id"):
        HC.export_tree(str(r), "HEAD", "", str(tmp_path / "out"))


def test_guard_n1_shallow_clone_reproduces_truthfully(fake, tmp_path):
    r = mkrepo(tmp_path / "repo", {"hook.c": GENUINE_C})
    (r / "hook.c").write_bytes(GENUINE_C + b"/* v2 */\n")
    git(r, "commit", "-qam", "v2")
    assert hookc("build", "--git", r, *TC, "--out", tmp_path / "o") == 0
    git(tmp_path, "clone", "-q", "--depth", "1", "file://" + str(r), str(tmp_path / "shallow"))
    assert gtxt(tmp_path / "shallow", "rev-parse", "--is-shallow-repository") == "true"
    assert hookc("reproduce", "--metadata", tmp_path / "o" / "0.hook.metadata.json", "--git", tmp_path / "shallow",
                 *ARM) == 0


def test_guard_n1_sha256_repository(fake, tmp_path):
    r = tmp_path / "r256"
    r.mkdir()
    git(r, "init", "-q", "--object-format=sha256")
    git(r, "config", "user.email", "rt@x")
    git(r, "config", "user.name", "rt")
    (r / "hook.c").write_bytes(GENUINE_C)
    git(r, "add", "-A")
    git(r, "commit", "-qm", "c")
    assert hookc("build", "--git", r, *TC, "--out", tmp_path / "o") == 0
    d = load(tmp_path / "o" / "0.hook.metadata.json")
    assert len(d["source"]["vcs"]["commit"]) == 64 and d["source"]["vcs"]["tree"] == gtxt(r, "rev-parse", "HEAD^{tree}")
    assert hookc("reproduce", "--metadata", tmp_path / "o" / "0.hook.metadata.json", "--git", r, *ARM) == 0


def test_guard_n1_malformed_trees_refused():
    f = "sha1"
    with pytest.raises(HC.HookcError):
        HC.parse_tree(b"100644 a\0" + b"\1" * 5, f)
    with pytest.raises(HC.HookcError, match="duplicate"):
        HC.parse_tree((b"100644 a\0" + b"\1" * 20) * 2, f)
    with pytest.raises(HC.HookcError, match="invalid"):
        HC.parse_tree(b"100644 a/b\0" + b"\1" * 20, f)
    assert HC.parse_tree(b"100644 a\0" + b"\1" * 20, f) == [("100644", b"a", "01" * 20)]


def test_guard_n1_object_store_that_lies_is_refused(monkeypatch):
    # git itself serving other bytes under a requested id (a replace ref, a planted object that
    # git does not verify, a patched git): hookc re-hashes every object it is handed
    oid = hashlib_sha1(b"blob 3\0abc")
    real = HC._git

    def lying(repo, *args, **kw):
        if args[:2] == ("cat-file", "--batch"):
            return b"%s blob 3\nabd\n" % oid.encode()
        return real(repo, *args, **kw)
    monkeypatch.setattr(HC, "_git", lying)
    with pytest.raises(HC.HookcError, match="does not hash to its id"):
        HC._cat_objects(".", [oid], "sha1")
    with pytest.raises(HC.HookcError, match="not a sha256 id"):
        HC._cat_objects(".", [oid], "sha256")


def hashlib_sha1(b):
    import hashlib
    return hashlib.sha1(b).hexdigest()


def test_guard_n1_unknown_object_format_refused(monkeypatch, tmp_path):
    r = mkrepo(tmp_path / "repo", {"hook.c": GENUINE_C})
    real = HC._git
    monkeypatch.setattr(HC, "_git", lambda repo, *a, **k: "sha999" if a == ("rev-parse", "--show-object-format")
                        else real(repo, *a, **k))
    with pytest.raises(HC.HookcError, match="unsupported object format"):
        HC.git_repo_check(str(r))


# ---------------- N3: checkout-converting gitattributes are refused ----------------

IDENT_C = (b'#include "hookapi.h"\nstatic const char id[] = "$Id$";\n'
           b'int64_t hook(uint32_t r) { _g(1,1); return accept(0, 0, sizeof(id) == 5 ? 1000000 : 10); }\n')


def test_rt2_n3_ident_attribute_worktree_build_refused(fake, tmp_path):
    # n3_ident_worktree_divergence.sh: the checkout says "$Id: <sha> $", the blob says "$Id$"
    r = mkrepo(tmp_path / "repo", {".gitattributes": b"hook.c ident\n", "hook.c": IDENT_C})
    (r / "hook.c").unlink()
    git(r, "checkout", "--", "hook.c")
    assert b"$Id: " in (r / "hook.c").read_bytes() and gtxt(r, "status", "--porcelain") == ""
    assert hookc("build", r, *TC, "--out", tmp_path / "o") == 3
    assert hookc("build", "--git", r, *TC, "--out", tmp_path / "o2") == 3


@pytest.mark.parametrize("attrs", [b"*.c ident\n", b"* filter=lfs\n", b"*.c eol=crlf\n", b"* text=auto\n",
                                   b"*.h text\n", b"*.c crlf\n", b"*.txt working-tree-encoding=UTF-16\n",
                                   b"* export-subst\n", b"[attr]mine ident\n*.c mine\n",
                                   b'"hook.c" ident\n'])
def test_rt2_n3_converting_attributes_refused_at_any_level(fake, tmp_path, attrs):
    r = mkrepo(tmp_path / "repo", {".gitattributes": attrs, "sub/hook.c": HOOK_C})
    assert hookc("build", "--git", r, "--path", "sub", *TC, "--out", tmp_path / "o") == 3
    r2 = mkrepo(tmp_path / "repo2", {"sub/.gitattributes": attrs, "sub/hook.c": HOOK_C})
    assert hookc("build", "--git", r2, "--path", "sub", *TC, "--out", tmp_path / "o2") == 3
    r3 = mkrepo(tmp_path / "repo3", {"hook.c": HOOK_C, "inc/.gitattributes": attrs, "inc/x.h": b"\n"})
    assert hookc("build", "--git", r3, *TC, "--out", tmp_path / "o3") == 3


def test_rt2_n3_local_info_attributes_refused(fake, tmp_path):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    (r / ".git" / "info").mkdir(exist_ok=True)
    (r / ".git" / "info" / "attributes").write_text("*.c ident\n")
    assert hookc("build", r, *TC, "--out", tmp_path / "o") == 3


@pytest.mark.parametrize("attrs", [b"*.c -text\n", b"*.wasm binary\n", b"*.c !eol\n", b"*.md diff=markdown\n",
                                   b"# *.c ident\n", b"*.c linguist-language=C\n"])
def test_guard_n3_harmless_attributes_accepted(fake, tmp_path, attrs):
    r = mkrepo(tmp_path / "repo", {".gitattributes": attrs, "hook.c": HOOK_C})
    assert hookc("build", "--git", r, *TC, "--out", tmp_path / "o") == 0


# ---------------- N6: the sidecar records the twins actually built ----------------

def test_rt2_n6_sidecar_records_only_the_twins_built(fake, tmp_path):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    assert hookc("build", "--git", r, *TC, "--out", tmp_path / "one") == 0
    d = load(tmp_path / "one" / "0.hook.metadata.json")
    assert d["builder"]["platforms_built"] == ["linux/arm64"]
    assert sorted(d["builder"]["platforms"]) == ["linux/amd64", "linux/arm64"]  # pins, not a build claim
    assert hookc("build", "--git", r, "--toolchain", "hookc-llvm22", "--out", tmp_path / "all") == 0
    assert load(tmp_path / "all" / "0.hook.metadata.json")["builder"]["platforms_built"] == ["linux/amd64", "linux/arm64"]


@pytest.mark.parametrize("built,odd", [("linux/arm64", "-amd64"), ("linux/amd64", "hookc-llvm22")])
def test_guard_n6_forged_platforms_built_is_rechecked_by_reproduce(fake, tmp_path, monkeypatch, built, odd):
    real = B.run_container

    def per_arch(recipe, image, src_dir, out_dir, params, timeout=None, vendor_dir=None):
        w = real(recipe, image, src_dir, out_dir, params, timeout, vendor_dir)
        if recipe["name"].endswith(odd):  # this twin would NOT reproduce the other twin's bytes
            w = w + bytes([0, 2, 1, 0x61])
            with open(os.path.join(out_dir, "hook.wasm"), "wb") as f:
                f.write(w)
        return w
    monkeypatch.setattr(B, "run_container", per_arch)
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    assert hookc("build", "--git", r, "--toolchain", "hookc-llvm22", "--platform", built, "--out", tmp_path / "o") == 0
    m = str(tmp_path / "o" / "0.hook.metadata.json")
    assert hookc("reproduce", "--metadata", m, "--git", r) == 0  # rebuilds exactly the recorded twin
    d = load(m)
    d["builder"]["platforms_built"] = ["linux/amd64", "linux/arm64"]  # claim a cross-check never done
    assert hookc("reproduce", "--metadata", save(tmp_path / "forged.json", d), "--git", r) == 2


def test_rt2_n6_single_twin_reproduce_says_platforms_built_not_rechecked(fake, tmp_path):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    assert hookc("build", "--git", r, "--toolchain", "hookc-llvm22", "--out", tmp_path / "o") == 0
    m = str(tmp_path / "o" / "0.hook.metadata.json")
    rep = HC.reproduce(m, git=str(r), platform="linux/amd64", log=lambda *_: None)
    assert rep["verdict"] == "REPRODUCED" and rep["platforms_built_rechecked"] is False
    assert "NOT re-checked" in rep["reason"] and rep["platforms_rebuilt"] == ["linux/amd64"]
    rep = HC.reproduce(m, git=str(r), log=lambda *_: None)
    assert rep["verdict"] == "REPRODUCED" and rep["platforms_built_rechecked"] is True
    assert rep["platforms_rebuilt"] == ["linux/amd64", "linux/arm64"]


@pytest.mark.parametrize("value", [[], ["linux/arm64", "linux/amd64"], ["linux/riscv64"], "linux/arm64", None,
                                   ["linux/arm64", "linux/arm64"]])
def test_rt2_n6_malformed_platforms_built_refused(fake, tmp_path, value):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    assert hookc("build", "--git", r, *TC, "--out", tmp_path / "o") == 0
    d = load(tmp_path / "o" / "0.hook.metadata.json")
    d["builder"]["platforms_built"] = value
    assert hookc("reproduce", "--metadata", save(tmp_path / "bad.json", d), "--git", r, *ARM) == 3


def test_guard_n6_make_metadata_refuses_unbuilt_claims():
    for built in ([], ["linux/arm64", "linux/arm64"], ["linux/arm64"]):
        with pytest.raises(HC.HookcError, match="platforms_built"):
            HC.make_metadata(HC.normalize_decls({})[0], rd("tiny.wasm"), None, HC.NO_WCE_REASON, "xhc-bin127", None,
                             {"CLANG_OPT": "-O2", "STAGES": "opt,clean", "WASMOPT": "-O2"}, "", {}, built)


# ---------------- N2: file names can never become compiler arguments ----------------

INJECT_C = (b'#include "hookapi.h"\n#ifndef LIMIT\n#define LIMIT 10   /* reviewed value */\n#endif\n'
            b'int64_t hook(uint32_t r) { _g(1,1); return accept(0, 0, LIMIT); }\n')


def test_rt2_n2_flag_injecting_file_name_refused(fake, tmp_path):
    # n2_filename_flag_injection.sh: a committed '-DLIMIT=1000000 -Wno-x.c' became clang flags
    r = mkrepo(tmp_path / "repo", {"hook.c": INJECT_C, "-DLIMIT=1000000 -Wno-x.c": b"/* release notes */\n"})
    assert hookc("build", "--git", r, *TC, "--out", tmp_path / "o") == 3
    assert fake["seen"] == []  # refused before any container ran


META = ["*", "?", "[", "]", "{", "}", "$", "`", "'", '"', "\\", ";", "&", "|", "<", ">", "(", ")", "~", "!", "#", "%"]


@pytest.mark.parametrize("name", ["-x.c", "sub/-o.h", "a b.c", "nbsp\u00a0x.c", "x\u2028y.c",
                                  "zw\u200bj.c"] + ["m%sx.c" % ch for ch in META if ch != "\\"])
def test_rt2_n2_unsafe_names_refused(fake, tmp_path, name):
    unsafe_name_refused(fake, tmp_path, name)


@pytest.mark.parametrize("name", ["tab\there.c", "m\\x.c"])  # already refused by round 1 (control char, backslash)
def test_guard_n2_round1_unsafe_names_still_refused(fake, tmp_path, name):
    unsafe_name_refused(fake, tmp_path, name)


def unsafe_name_refused(fake, tmp_path, name):
    r = tmp_path / "repo"
    mkrepo(r, {"hook.c": HOOK_C})
    b = blob_w(r, b"x\n")
    ents = [("100644", "blob", gtxt(r, "rev-parse", "HEAD:hook.c"), b"hook.c"),
            ("100644", "blob", b, name.encode())]
    t = crafted_tree(r, ents)
    c = git(r, "commit-tree", t, "-m", "x").decode().strip()
    assert hookc("build", "--git", r, "--rev", c, *TC, "--out", tmp_path / "o") == 3


def crafted_tree(r, ents):
    """mktree for flat or one-level-nested names (git mktree refuses '/' in a name)."""
    top, sub = [], {}
    for mode, kind, oid, name in ents:
        if b"/" in name:
            d, n = name.split(b"/", 1)
            sub.setdefault(d, []).append((mode, kind, oid, n))
        else:
            top.append((mode, kind, oid, name))
    for d, es in sub.items():
        top.append(("040000", "tree", crafted_tree(r, es), d))
    data = b"".join(b"%s %s %s\t%s\0" % (m.encode(), k.encode(), o.encode(), n) for m, k, o, n in top)
    return git(r, "mktree", "-z", input=data).decode().strip()


@pytest.mark.parametrize("name", ["hook.c", "hook_v2.c", "a+b.c", "sub/x.h", "日本語.h", "Makefile", ".clang-format"])
def test_guard_n2_plain_names_accepted(fake, tmp_path, name):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C, name: HOOK_C})
    assert hookc("build", "--git", r, *TC, "--out", tmp_path / "o") == 0


C_PIPELINES = ["hookc-llvm22", "hookc-llvm22-amd64", "kvt-llvm22", "kvt-llvm22-amd64", "xhc-bin127"]


def pipeline_source_block(recipe):
    s = open(os.path.join(B.RECIPES_DIR, recipe, "pipeline.sh")).read()
    start = s.index("set --\n")
    end = s.index("done\n", s.index('for f in "$@"; do')) + len("done\n")
    return s[start:end]


def run_block(recipe, files, entry=""):
    d = files
    script = "set -eu\n" + pipeline_source_block(recipe) + 'printf "%s\\0" "$@"\n'
    r = subprocess.run(["/bin/sh", "-c", script], cwd=d, capture_output=True, env={"PATH": os.environ["PATH"],
                                                                                  "ENTRY": entry, "LC_ALL": "C"})
    return r.returncode, r.stdout.split(b"\0")[:-1]


@pytest.mark.parametrize("recipe", C_PIPELINES)
def test_rt2_n2_pipelines_pass_sources_as_quoted_arguments_after_double_dash(recipe, tmp_path):
    s = open(os.path.join(B.RECIPES_DIR, recipe, "pipeline.sh")).read()
    assert "$SOURCES" not in s and "$CLANG_CMD;" not in s and "\n$CLANG_CMD\n" not in s
    assert '$CLANG_FLAGS -- "$@"' in s
    (tmp_path / "b.c").write_text("")
    (tmp_path / "a.c").write_text("")
    (tmp_path / "Z.c").write_text("")
    (tmp_path / "x.h").write_text("")
    assert run_block(recipe, tmp_path) == (0, [b"Z.c", b"a.c", b"b.c"])
    (tmp_path / "-DLIMIT=1000000 -Wno-x.c").write_text("")
    assert run_block(recipe, tmp_path)[0] == 4


@pytest.mark.parametrize("recipe", C_PIPELINES)
@pytest.mark.parametrize("bad", ["a b.c", "x\ny.c", "$(id).c", "*.c", "-o.c"])
def test_rt2_n2_pipelines_refuse_unsafe_source_names(recipe, bad, tmp_path):
    (tmp_path / "ok.c").write_text("")
    (tmp_path / bad).write_text("")
    if "\n" in bad:
        (tmp_path / "y.c").write_text("")
    assert run_block(recipe, tmp_path)[0] == 4


@pytest.mark.parametrize("recipe", C_PIPELINES[:4])
def test_rt2_n2_llvm_pipelines_entry_is_one_argument(recipe, tmp_path):
    (tmp_path / "hook.c").write_text("")
    (tmp_path / "other.c").write_text("")
    assert run_block(recipe, tmp_path, "hook.c") == (0, [b"hook.c"])
    assert run_block(recipe, tmp_path, "-ohook.c")[0] == 4
    assert run_block(recipe, tmp_path, "missing.c")[0] == 4


@pytest.mark.parametrize("recipe", C_PIPELINES[:4])
def test_rt2_n2_entry_param_cannot_start_with_dash(recipe):
    with pytest.raises(B.BuildError):
        B.resolve_params(B.load_recipe(recipe), {"ENTRY": "-DX.c"})
    assert HC.ENTRY_RE.match("-DX.c") is None


# ---------------- N5: the compiler cannot see the build host's /proc or /sys ----------------

N5_C = (b'#include "hookapi.h"\n#if __has_include("/sys/devices/system/cpu/cpu0/cpu_capacity")\n'
        b'#define LIMIT 1000000\n#else\n#define LIMIT 10\n#endif\n'
        b'int64_t hook(uint32_t r) { _g(1,1); return accept(0, 0, LIMIT); }\n')


def test_rt2_n5_source_probing_host_sysfs_refused(fake, tmp_path):
    # n5_host_kernel_embed.sh: bytes depended on the build host's kernel
    r = mkrepo(tmp_path / "repo", {"hook.c": N5_C})
    assert hookc("build", "--git", r, "--toolchain", "hookc-llvm22", "--out", tmp_path / "o") == 3
    assert fake["seen"] == []


@pytest.mark.parametrize("src", [
    b'#include "/proc/version"\n', b'  #  include </etc/hostname>\n', b'%:include "/proc/cpuinfo"\n',
    b'#include_next </sys/x>\n', b'#import "/proc/x"\n', b'#embed "/dev/urandom" limit(8)\n',
    b'#if __has_embed(</proc/version>)\n#endif\n', b'#if __has_include_next("/sys/x")\n#endif\n',
    b'#inc\\\nlude "/proc/version"\n', b'# /* c */ include "/proc/version"\n',
    b'__asm__(".incbin \\"/proc/version\\"");\n', b'#include "\\\n/proc/version"\n'])
def test_rt2_n5_absolute_include_like_operands_refused(fake, tmp_path, src):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C, "inc/x.h": src})
    assert hookc("build", "--git", r, *TC, "--out", tmp_path / "o") == 3


@pytest.mark.parametrize("src", [b'#include "hookapi.h"\n', b'#include <sub/x.h>\n', b'// #include "/proc/x"\n',
                                 b'/* #include "/proc/x" */\n', b'const char *p = "/proc/version";\n',
                                 b'#include "inc2/x.h"\n', b'const char *q = "../x";\n'])
def test_guard_n5_ordinary_sources_accepted(fake, tmp_path, src):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C, "inc/x.h": src})
    assert hookc("build", "--git", r, *TC, "--out", tmp_path / "o") == 0


def docker_cmd(monkeypatch, recipe_name, vendor=None):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 1, "", "stop")
    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(B.BuildError):
        B.run_container(B.load_recipe(recipe_name), {"image_id": "sha256:img"}, FX, fresh_dir(), {}, vendor_dir=vendor)
    return calls[0]


@pytest.mark.parametrize("recipe", C_PIPELINES)
def test_rt2_n5_c_pipelines_run_chrooted_without_proc_and_sys(monkeypatch, recipe):
    cmd = docker_cmd(monkeypatch, recipe)
    i = cmd.index("sha256:img")
    assert cmd[i + 1:i + 3] == ["chroot", "/jail"] and cmd[i + 3:] == ["/bin/sh", "/tc/pipeline.sh"]
    assert ["--tmpfs", "/sys:ro,size=4k"] == cmd[cmd.index("/sys:ro,size=4k") - 1:cmd.index("/sys:ro,size=4k") + 1]
    mounts = [cmd[k + 1] for k, a in enumerate(cmd) if a in ("-v", "--tmpfs")]
    assert all(m.split(":")[0].startswith("/jail/") or m.split(":")[1].startswith("/jail/") or m.startswith("/sys:")
               for m in mounts)
    assert "--read-only" in cmd and cmd[cmd.index("--network") + 1] == "none"
    df = B.dockerfile_text(B.load_recipe(recipe))
    assert "COPY tc/ /jail/tc/" in df and "COPY tc/ /tc/" not in df and B.JAIL_ABI in df
    setup = [ln for ln in df.splitlines() if ln.startswith("RUN --network=none mkdir /jail")][0]
    assert "/proc|/sys|/dev|" in setup and "rm -f /jail/etc/hostname /jail/etc/hosts /jail/etc/resolv.conf" in setup


def test_guard_n5_non_jail_recipes_unchanged(monkeypatch):
    cmd = docker_cmd(monkeypatch, "rshooks-0.2.3", vendor="/v")
    assert "chroot" not in cmd and cmd[-2:] == ["/bin/sh", "/tc/pipeline.sh"]
    assert "%s:/vendor:ro" % os.path.abspath("/v") in cmd and "/sys:ro,size=4k" not in cmd
    assert "COPY tc/ /tc/" in B.dockerfile_text(B.load_recipe("hookc-wce"))


def test_guard_n5_jail_flag_validated():
    r = {k: v for k, v in B.load_recipe("kvt-llvm22").items() if not k.startswith("_")}
    with pytest.raises(B.BuildError, match="jail"):
        B.validate_recipe(dict(r, jail="yes"))

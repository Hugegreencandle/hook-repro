"""Regression tests for the 2026-09-28 hostile red-team of hookc / hook-repro (round 1).

Each test is the offline form of one RT repro script (scratchpad/rt/*.sh|*.py): same inputs,
driven through the CLI where the script used the CLI, with docker replaced by a FAKE
CONTAINER that "compiles" exactly the directory it is handed (every file except .git/), so
anything the container receives changes the output bytes. Expectations are literals (exit
codes 0/2/3, verdict strings, file absence). Every test here fails on b571bb2.

  FP1/FP2  sidecar source.vcs / source.entry never checked by reproduce --src
  FP3      verify --metadata ignores sidecar HookHash / WCE / HookOn / builder fields
  FP4      work-tree builds compile ignored / skip-worktree content under a clean commit id
  FP5      case-fold (and NFC/NFD) collisions collapse on macOS exports
  FP6      builder.preset is a free label
  F6/F7    tree_sha256 skips __pycache__/.git/.hook-repro that the container still receives
  C1/C2    export path escape (absolute, ..) and non-UTF-8 names (traceback)
  FN1      core.autocrlf work-tree build can never be reproduced from git
  L1/O3    two self-reported node keys from one backend pass as two operators
  L2/O5    cache trusted without re-hash; docker tag trusted; code version not in digest
  L3       HookName length rule weaker than rshooks'
  L4       operator agreement compared ReferenceCount (whole definition)
  O1/O2    README overclaims rshooks compatibility; chain null undocumented; book fixture
"""
import copy
import hashlib
import json
import os
import subprocess
import urllib.error
import urllib.request

import pytest

from hook_repro import build as B, cli, fetch as F, hookc as HC, verify as V
from hook_repro.hashing import sha512half

FX = os.path.join(os.path.dirname(__file__), "fixtures")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
H_CR = "805351CE26FB79DA00647CEFED502F7E15C2ACCCE254F11DEFEDDCE241F8E9CA"  # ledger HookHash field
H_OTHER = "0123456789ABCDEF" * 4  # synthetic: some other HookHash
MAIN = ["https://xahau.network", "https://cluster.cbotlabs.xyz"]
TC = ["--toolchain", "hookc-llvm22", "--platform", "linux/arm64"]
FAKE_LOG = ("clang_version: fake-clang 1\nwasm_opt_version: fake-opt 1\nHOOKC_WASM_OPT_RAN=0\n--- commands\n"
            "cc -o hook.wasm *.c\n")
HOOK_C = b'#include "hookapi.h"\nint64_t hook(uint32_t r) { _g(1,1); return accept(0, 0, 0); }\n'


def rd(*p):
    with open(os.path.join(FX, *p), "rb") as f:
        return f.read()


def git(repo, *a, **kw):
    return subprocess.run(["git", "-C", str(repo)] + list(a), check=True, capture_output=True, **kw).stdout


def gtxt(repo, *a):
    return git(repo, *a).decode().strip()


def mkrepo(path, files):
    path.mkdir(parents=True, exist_ok=True)
    git(path.parent, "init", "-q", str(path))
    git(path, "config", "user.email", "rt@x")
    git(path, "config", "user.name", "rt")
    git(path, "config", "core.autocrlf", "false")
    for name, data in files.items():
        (path / name).parent.mkdir(parents=True, exist_ok=True)
        (path / name).write_bytes(data)
    git(path, "add", "-A")
    git(path, "commit", "-qm", "init")
    return path


def container_view(src_dir):
    """What `cp -R /src/. /work/src/` hands the compiler (a .git dir cannot affect clang)."""
    out = []
    for dp, dn, fn in os.walk(src_dir):
        dn[:] = [d for d in dn if d != ".git"]
        for f in fn:
            full = os.path.join(dp, f)
            with open(full, "rb") as fh:
                out.append((os.path.relpath(full, src_dir).replace(os.sep, "/"), hashlib.sha256(fh.read()).hexdigest()))
    return sorted(out)


def fake_wasm(view, params):
    """tiny.wasm (exports hook) + a custom section carrying a digest of everything compiled."""
    digest = hashlib.sha256(json.dumps([view, sorted(params.items())]).encode()).digest()
    payload = bytes([3]) + b"src" + digest
    return rd("tiny.wasm") + bytes([0, len(payload)]) + payload


@pytest.fixture
def fake(monkeypatch, tmp_path):
    """Docker replaced by a container that compiles exactly what it receives."""
    seen = []
    state = {"wasm": None}

    def run_container(recipe, image, src_dir, out_dir, params, timeout=None, vendor_dir=None):
        view = container_view(src_dir)
        seen.append(view)
        wasm = state["wasm"] or fake_wasm(view, params)
        with open(os.path.join(out_dir, "hook.wasm"), "wb") as f:
            f.write(wasm)
        with open(os.path.join(out_dir, "build.txt"), "w") as f:
            f.write(FAKE_LOG)
        return wasm

    monkeypatch.setattr(B, "CACHE", str(tmp_path / "cache"))
    monkeypatch.setattr(B, "run_container", run_container)
    monkeypatch.setattr(B, "ensure_image", lambda recipe, log=print: {
        "tag": "t", "image_id": "sha256:fake", "recipe_digest": B.recipe_digest(recipe)})
    monkeypatch.setattr(B, "docker_available", lambda: True)
    monkeypatch.setattr(HC, "run_wce", lambda w, log=None: ({"hook": 149, "cbak": 7}, None))
    state["seen"] = seen
    return state


def hookc(*args):
    return cli.main(["hookc"] + [str(a) for a in args])


def load(p):
    with open(p) as f:
        return json.load(f)


def save(p, doc):
    with open(p, "w") as f:
        f.write(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    return str(p)


# ---------------- FP1 / O4: source.vcs must be what is rebuilt ----------------

def test_rt_fp1_reproduce_rebuilds_only_the_sidecar_commit(fake, tmp_path):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    assert hookc("build", "--git", r, *TC, "--out", tmp_path / "o") == 0
    d = load(tmp_path / "o" / "0.hook.metadata.json")
    d["source"]["vcs"].update(commit="1" * 40, tree="2" * 40, path="some/other/project")
    m = save(tmp_path / "fp1.json", d)
    assert hookc("reproduce", "--metadata", m, "--src", r, "--platform", "linux/arm64") == 3
    assert hookc("reproduce", "--metadata", m, "--git", r, "--platform", "linux/arm64") == 3


def test_rt_fp1_src_must_be_a_git_work_tree_at_the_sidecar_tree(fake, tmp_path):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    assert hookc("build", "--git", r, *TC, "--out", tmp_path / "o") == 0
    m = str(tmp_path / "o" / "0.hook.metadata.json")
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "hook.c").write_bytes(HOOK_C)  # same bytes, no git: not provenance
    assert hookc("reproduce", "--metadata", m, "--src", plain, "--platform", "linux/arm64") == 3
    (r / "hook.c").write_bytes(HOOK_C + b"// later\n")
    git(r, "commit", "-qam", "later")  # HEAD tree is no longer the sidecar's
    assert hookc("reproduce", "--metadata", m, "--src", r, "--platform", "linux/arm64") == 3
    assert hookc("reproduce", "--metadata", m, "--git", r, "--platform", "linux/arm64") == 0


# ---------------- FP2: source.entry must be the entry compiled ----------------

def test_rt_fp2_entry_must_be_the_compiled_entry(fake, tmp_path):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C, "other.c": HOOK_C})
    assert hookc("build", "--git", r, *TC, "--entry", "hook.c", "--out", tmp_path / "o") == 0
    m = str(tmp_path / "o" / "0.hook.metadata.json")
    assert hookc("reproduce", "--metadata", m, "--git", r, "--platform", "linux/arm64") == 0
    d = load(m)
    d["source"]["entry"] = "other.c"
    assert hookc("reproduce", "--metadata", save(tmp_path / "fp2.json", d), "--src", r, "--platform", "linux/arm64") == 3


def test_rt_fp2_entry_given_as_param_is_recorded(fake, tmp_path):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C, "other.c": HOOK_C})
    assert hookc("build", "--git", r, *TC, "--param", "ENTRY=hook.c", "--out", tmp_path / "o") == 0
    d = load(tmp_path / "o" / "0.hook.metadata.json")
    assert d["builder"]["params"] == {"ENTRY": "hook.c"} and d["source"]["entry"] == "hook.c"


# ---------------- FP3 / L4: verify --metadata enforces the sidecar ----------------

def recorded():
    out = {}
    for host in ("xahau.network", "cluster.cbotlabs.xyz"):
        with open(os.path.join(FX, "rec_%s.json" % host)) as f:
            out["https://" + host] = json.load(f)
    return out


def use_chain(monkeypatch, rec):
    def t(url, payload, timeout=20):
        return copy.deepcopy(rec[url]["server_info"] if payload["method"] == "server_info" else rec[url]["ledger_entry"])
    monkeypatch.setattr(F, "http_transport", t)


def claimreward_sidecar(fake, tmp_path):
    fake["wasm"] = rd("claimreward_onledger.wasm")  # the compiler of this fake emits the on-ledger bytes
    r = mkrepo(tmp_path / "cr", {"claimReward.c": b"/* claimReward */\n"})
    assert hookc("build", "--git", r, "--toolchain", "xhc-bin127", "--preset", "classic", "--on", "Cron",
                 "--can-emit", "ClaimReward", "--out", tmp_path / "cro") == 0
    return r, str(tmp_path / "cro" / "0.hook.metadata.json")


def verify_cli(r, m, out):
    return cli.main(["verify", "--hookhash", H_CR, "--src", str(r), "--metadata", m, "--platform", "linux/amd64",
                     "--out", str(out)])


def test_rt_fp3_honest_sidecar_verifies(fake, tmp_path, monkeypatch):
    r, m = claimreward_sidecar(fake, tmp_path)
    use_chain(monkeypatch, recorded())
    assert verify_cli(r, m, tmp_path / "v") == 0
    rep = load(tmp_path / "v" / "verify-report.json")
    assert rep["verdict"] == "REPRODUCED" and rep["metadata_hookhash_matches"] is True


def test_rt_fp3_sidecar_describing_another_hook_is_refused(fake, tmp_path, monkeypatch):
    r, m = claimreward_sidecar(fake, tmp_path)
    use_chain(monkeypatch, recorded())
    d = load(m)
    d["HookHash"] = H_OTHER  # a different hook
    d["WCE"] = {"hook": 1, "cbak": 0}
    d["HookOn"] = "0" * 64
    d["human"]["on"] = {"form": "all", "HookOn": None, "HookOnIncoming": None, "HookOnOutgoing": None}
    d["builder"]["cc"] = "clang version 99.0.0 (totally different compiler)"
    d["builder"]["commands"] = ["cat prebuilt.wasm"]
    assert verify_cli(r, save(tmp_path / "lie.json", d), tmp_path / "v") == 3
    assert load(tmp_path / "v" / "verify-report.json")["verdict"] == "UNVERIFIED"


@pytest.mark.parametrize("path,value", [
    (["WCE", "hook"], 1),
    (["builder", "cc"], "clang version 99.0.0 (totally different compiler)"),
    (["builder", "commands"], ["cat prebuilt.wasm"]),
    (["source", "file_count"], 7),
])
def test_rt_fp3_sidecar_field_lies_are_mismatch(fake, tmp_path, monkeypatch, path, value):
    r, m = claimreward_sidecar(fake, tmp_path)
    use_chain(monkeypatch, recorded())
    d = load(m)
    cur = d
    for k in path[:-1]:
        cur = cur[k]
    cur[path[-1]] = value
    assert verify_cli(r, save(tmp_path / "lie.json", d), tmp_path / "v") == 2
    assert load(tmp_path / "v" / "verify-report.json")["verdict"] == "MISMATCH"


@pytest.mark.parametrize("field,value", [("Fee", "150"), ("HookCallbackFee", "8")])  # HookOn: RT2 N4
def test_rt_fp3_hookdefinition_disagreement_is_mismatch(fake, tmp_path, monkeypatch, field, value):
    r, m = claimreward_sidecar(fake, tmp_path)
    rec = recorded()
    for u in MAIN:
        rec[u]["ledger_entry"]["result"]["node"][field] = value
    use_chain(monkeypatch, rec)
    assert verify_cli(r, m, tmp_path / "v") == 2


def test_rt_fp3_hookcanemit_difference_is_reported_not_enforced(fake, tmp_path, monkeypatch):
    # the on-ledger ClaimReward definition carries the author's 65-char typo mask (truncated)
    r, m = claimreward_sidecar(fake, tmp_path)
    use_chain(monkeypatch, recorded())
    assert verify_cli(r, m, tmp_path / "v") == 0
    rows = {x["definition"]: (x["match"], x["enforced"]) for x in
            load(tmp_path / "v" / "verify-report.json")["definition_check"]["fields"]}
    assert rows == {"Fee": (True, True), "HookCallbackFee": (True, True), "HookOn": (True, False),
                    "HookCanEmit": (False, False)}


def test_rt_l4_operator_agreement_ignores_reference_count():
    node = recorded()[MAIN[0]]["ledger_entry"]["result"]["node"]
    d0 = {k: v for k, v in node.items() if k != "CreateCode"}
    reads = [{"definition": d0}, {"definition": dict(d0, ReferenceCount="99")}]
    doc = {"WCE": {"hook": 149, "cbak": 7}, "HookOn": node["HookOn"], "HookCanEmit": None}
    rows = {r["definition"]: r["match"] for r in V.definition_check(doc, reads)["fields"]}
    assert rows == {"Fee": True, "HookCallbackFee": True, "HookOn": True, "HookCanEmit": None}
    reads[1]["definition"]["Fee"] = "150"
    assert "fields" not in V.definition_check(doc, reads)


def test_rt_fp3_rshooks_sidecar_for_another_hash_is_unverified():
    from test_core import fake_builder, transport_from
    good = rd("claimreward_onledger.wasm")
    meta = {"hookhash": H_OTHER}
    r = V.verify(H_CR, FX, "xhc-bin127", "mainnet", transport=transport_from(recorded()),
                 builder=fake_builder([good, good]), endpoints=MAIN, metadata=meta)
    assert r["verdict"] == "UNVERIFIED" and r["builds"] == []


# ---------------- FP4 / FN1: a versioned build compiles the commit, not the work tree ----------------

FP4_C = (b'#include "hookapi.h"\n__attribute__((weak)) const int64_t LIMIT = 10;\n'
         b'int64_t hook(uint32_t r) { _g(1,1); return accept(0, 0, LIMIT); }\n')


def test_rt_fp4_gitignored_file_is_not_compiled(fake, tmp_path):
    r = mkrepo(tmp_path / "repo", {"hook.c": FP4_C, ".gitignore": b"*_local.c\n"})
    assert hookc("build", "--git", r, *TC, "--out", tmp_path / "honest") == 0
    honest = load(tmp_path / "honest" / "0.hook.metadata.json")["HookHash"]
    (r / "zz_local.c").write_bytes(b"const long long LIMIT = 1000000;\n")
    assert gtxt(r, "status", "--porcelain") == ""
    assert hookc("build", r, *TC, "--out", tmp_path / "a") == 0
    a = load(tmp_path / "a" / "0.hook.metadata.json")
    assert a["HookHash"] == honest
    assert all("zz_local.c" not in [p for p, _ in v] for v in fake["seen"])
    m = str(tmp_path / "a" / "0.hook.metadata.json")
    assert hookc("reproduce", "--metadata", m, "--git", r, "--platform", "linux/arm64") == 0
    # RT4 F2: the ignored zz_local.c is in the work tree a reviewer reads, so --src refuses it
    assert hookc("reproduce", "--metadata", m, "--src", r, "--platform", "linux/arm64") == 3


def test_rt_fp4_skip_worktree_edit_is_not_compiled(fake, tmp_path):
    r = mkrepo(tmp_path / "repo", {"hook.c": FP4_C})
    assert hookc("build", "--git", r, *TC, "--out", tmp_path / "honest") == 0
    honest = load(tmp_path / "honest" / "0.hook.metadata.json")["HookHash"]
    (r / "hook.c").write_bytes(FP4_C.replace(b"= 10;", b"= 99999;"))
    git(r, "update-index", "--skip-worktree", "hook.c")
    assert gtxt(r, "status", "--porcelain") == ""
    assert hookc("build", r, *TC, "--out", tmp_path / "b") == 0
    assert load(tmp_path / "b" / "0.hook.metadata.json")["HookHash"] == honest


def test_rt_fn1_autocrlf_clone_build_reproduces_from_git(fake, tmp_path):
    up = mkrepo(tmp_path / "up", {"hook.c": HOOK_C})
    win = tmp_path / "win"
    subprocess.run(["git", "clone", "-q", "-c", "core.autocrlf=true", str(up), str(win)], check=True)
    assert b"\r\n" in (win / "hook.c").read_bytes() and gtxt(win, "status", "--porcelain") == ""
    assert hookc("build", win, *TC, "--out", tmp_path / "o") == 0
    m = str(tmp_path / "o" / "0.hook.metadata.json")
    assert hookc("reproduce", "--metadata", m, "--git", up, "--platform", "linux/arm64") == 0


# ---------------- FP5 / C1 / C2 / F7: export safety ----------------

def commit_index(r, entries):
    """Commit blobs straight into the index (names a work tree may not be able to hold)."""
    args = []
    for name, data in entries:
        oid = subprocess.run(["git", "-C", str(r), "hash-object", "-w", "--stdin"], input=data,
                             capture_output=True, check=True).stdout.decode().strip()
        args += ["--cacheinfo", "100644,%s,%s" % (oid, name)]
    git(r, "update-index", "--add", *args)
    git(r, "commit", "-qm", "idx")
    return gtxt(r, "rev-parse", "HEAD")


def test_rt_fp5_casefold_collision_refused(fake, tmp_path, capsys):
    r = mkrepo(tmp_path / "repo", {"hook.c": b'#include "Cfg.h"\n' + HOOK_C})
    git(r, "config", "core.ignorecase", "false")
    x = commit_index(r, [("Cfg.h", b"#define LIMIT 10\n"), ("cfg.h", b"#define LIMIT 1000000\n")])
    assert sorted(gtxt(r, "ls-tree", "--name-only", x).split()) == ["Cfg.h", "cfg.h", "hook.c"]
    assert hookc("build", "--git", r, "--rev", x, *TC, "--out", tmp_path / "o") == 3
    assert "collide" in capsys.readouterr().err
    assert not (tmp_path / "o" / "0.hook.metadata.json").exists()


def test_rt_fp5_unicode_normalization_collision_refused(fake, tmp_path, capsys):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    git(r, "config", "core.precomposeunicode", "false")
    x = commit_index(r, [("café.h", b"#define A 1\n"), ("café.h", b"#define A 2\n")])
    assert hookc("build", "--git", r, "--rev", x, *TC, "--out", tmp_path / "o") == 3
    assert "collide" in capsys.readouterr().err


def crafted_commit(r, ents):
    """A tree object written with --literally: git's own checks are bypassed, like an attacker's."""
    body = b"".join(b"100644 " + n + b"\0" + bytes.fromhex(h) for n, h in sorted(ents))
    t = subprocess.run(["git", "-C", str(r), "hash-object", "-t", "tree", "--literally", "-w", "--stdin"],
                       input=body, capture_output=True, check=True).stdout.decode().strip()
    return gtxt(r, "commit-tree", t, "-m", "crafted")


def blob(r, data):
    return subprocess.run(["git", "-C", str(r), "hash-object", "-w", "--stdin"], input=data,
                          capture_output=True, check=True).stdout.decode().strip()


def test_rt_c1_export_path_escape_refused(fake, tmp_path):
    r = mkrepo(tmp_path / "repo", {"x": b"x"})
    target = tmp_path / "PWNED_abs.txt"
    b = blob(r, b"attacker-controlled bytes\n")
    c = crafted_commit(r, [(str(target).encode(), b), (b"../../PWNED_dotdot.txt", b), (b"hook.c", blob(r, HOOK_C))])
    assert hookc("build", "--git", r, "--rev", c, *TC, "--out", tmp_path / "o") == 3
    assert not target.exists()
    assert [p for p in (tmp_path / "cache").rglob("PWNED*")] == []


@pytest.mark.parametrize("name", [b".git/config", b".GIT/hooks.c", b"a\\b.c", b"a/./b.c", b"__pycache__/cfg.h",
                                  b"x/.hook-repro/y.h", b"tab\there.c"])
def test_rt_c1_reserved_or_unsafe_names_refused(fake, tmp_path, name):
    r = mkrepo(tmp_path / "repo", {"x": b"x"})
    c = crafted_commit(r, [(name, blob(r, b"x\n")), (b"hook.c", blob(r, HOOK_C))])
    assert hookc("build", "--git", r, "--rev", c, *TC, "--out", tmp_path / "o") == 3


def test_rt_c2_non_utf8_name_fails_closed(fake, tmp_path, capsys):
    r = mkrepo(tmp_path / "repo", {"x": b"x"})
    c = crafted_commit(r, [(b"bad\xffname", blob(r, b"x\n"))])
    assert hookc("build", "--git", r, "--rev", c, *TC, "--out", tmp_path / "o") == 3
    err = capsys.readouterr().err
    assert "UNVERIFIED" in err and "UTF-8" in err


def test_rt_f7_tree_hash_covers_exactly_what_the_container_receives(fake, tmp_path, capsys):
    out = {}
    for v, limit in (("A", b"10"), ("B", b"1000000")):
        d = tmp_path / v
        (d / "__pycache__").mkdir(parents=True)
        (d / "hook.c").write_bytes(b'#include "__pycache__/cfg.h"\n' + HOOK_C)
        (d / "__pycache__" / "cfg.h").write_bytes(b"#define LIMIT " + limit + b"\n")
        assert cli.main(["build", str(d), "--recipe", "hookc-llvm22", "--preset", "deploy",
                         "--out", str(tmp_path / ("out" + v))]) == 0
        out[v] = json.loads(capsys.readouterr().out)
        man = load(tmp_path / ("out" + v) / "build-manifest.json")
        assert fake["seen"][-1] == sorted(tuple(e) for e in man["source"]["files"])
    assert out["A"]["source_tree_sha256"] == out["B"]["source_tree_sha256"]
    assert out["A"]["output"]["sha512half"] == out["B"]["output"]["sha512half"]


# ---------------- FP6: preset label ----------------

def test_rt_fp6_preset_label_must_resolve_to_params(fake, tmp_path):
    r, m = claimreward_sidecar(fake, tmp_path)
    assert hookc("reproduce", "--metadata", m, "--git", r) == 0
    d = load(m)
    assert d["builder"]["preset"] == "classic"
    d["builder"]["preset"] = "builder-2025"
    assert hookc("reproduce", "--metadata", save(tmp_path / "fp6.json", d), "--git", r) == 3


def test_rt_fp6_overridden_params_drop_the_label(fake, tmp_path):
    r = mkrepo(tmp_path / "cr", {"claimReward.c": b"/* x */\n"})
    assert hookc("build", "--git", r, "--toolchain", "xhc-bin127", "--preset", "classic",
                 "--param", "CLANG_OPT=-O3", "--out", tmp_path / "o") == 0
    b = load(tmp_path / "o" / "0.hook.metadata.json")["builder"]
    assert b["preset"] is None and b["params"]["CLANG_OPT"] == "-O3"


# ---------------- L1 / O3: operator independence ----------------

def one_backend(ledger_hash=None, index=None):
    code = rd("tiny.wasm")
    H = sha512half(code)

    def t(url, payload):
        if payload["method"] == "server_info":
            return {"result": {"status": "success", "info": {"pubkey_node": "n9FAKE_" + url[-5:], "network_id": 21337}}}
        res = {"status": "success", "validated": True, "ledger_index": (index or {}).get(url, 1), "node": {
            "LedgerEntryType": "HookDefinition", "HookHash": H, "CreateCode": code.hex().upper()}}
        if ledger_hash:
            res["ledger_hash"] = ledger_hash[url]
        return {"result": res}
    return H, t


def test_rt_l1_reads_without_validated_ledger_hash_refused():
    H, t = one_backend()
    f = F.fetch_createcode(H, "xahau-mainnet", transport=t)
    assert f["ok"] is False and "ledger_hash" in f["reason"]


def test_rt_l1_operators_must_agree_on_the_validated_ledger_hash():
    H, t = one_backend({MAIN[0]: "A" * 64, MAIN[1]: "B" * 64})
    f = F.fetch_createcode(H, "xahau-mainnet", transport=t)
    assert f["ok"] is False and "DISAGREE on validated ledger" in f["reason"]
    H, t = one_backend({MAIN[0]: "A" * 64, MAIN[1]: "A" * 64})
    f = F.fetch_createcode(H, "xahau-mainnet", transport=t)
    assert f["ok"] is True and f["ledger_hash"] == "A" * 64 and f["ledger_index"] == 1


def test_rt_l1_newer_operator_is_reread_at_the_common_ledger():
    code = rd("tiny.wasm")
    H = sha512half(code)
    calls = []

    def t(url, payload):
        if payload["method"] == "server_info":
            return {"result": {"status": "success", "info": {"pubkey_node": "n9" + url[-5:], "network_id": 21337}}}
        li = payload["params"][0]["ledger_index"]
        calls.append((url, li))
        idx = {MAIN[0]: 101, MAIN[1]: 100}[url] if li == "validated" else li
        return {"result": {"status": "success", "validated": True, "ledger_index": idx,
                           "ledger_hash": "%064X" % idx, "node": {
                               "LedgerEntryType": "HookDefinition", "HookHash": H, "CreateCode": code.hex()}}}
    f = F.fetch_createcode(H, "xahau-mainnet", transport=t)
    assert f["ok"] is True and f["ledger_index"] == 100 and f["ledger_hash"] == "%064X" % 100
    assert calls == [(MAIN[0], "validated"), (MAIN[1], "validated"), (MAIN[0], 100)]


def test_rt_l1_recorded_mainnet_reads_share_one_ledger():
    from test_core import transport_from
    f = F.fetch_createcode(H_CR, "xahau-mainnet", transport=transport_from(recorded()), endpoints=MAIN)
    assert f["ok"] is True and f["ledger_index"] == 26134650
    assert f["ledger_hash"] == "01467F71BEF7E155948352DB1703E387BCCF8C8FEBB271C3876AC86A0E90DB7A"


# ---------------- L2 / O5: local cache, docker image, code version ----------------

def test_rt_l2_corrupted_cas_entry_is_not_used(tmp_path, monkeypatch):
    monkeypatch.setattr(B, "CACHE", str(tmp_path))
    a = {"name": "x", "url": "https://example.invalid/x", "sha256": "ab" * 32}
    p = os.path.join(str(tmp_path), "cas", a["sha256"])
    os.makedirs(os.path.dirname(p))
    with open(p, "w") as f:
        f.write("NOT THE PINNED BYTES")

    def no_net(*a, **k):
        raise urllib.error.URLError("offline test")
    monkeypatch.setattr(urllib.request, "urlopen", no_net)
    with pytest.raises(B.BuildError):
        B.fetch_artifact(a, log=lambda *_: None)
    assert not os.path.exists(p)


def test_rt_l2_rebound_docker_tag_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(B, "CACHE", str(tmp_path))
    r = B.load_recipe("hookc-wce")
    ran = []

    class R:
        def __init__(self, rc, out):
            self.returncode, self.stdout, self.stderr = rc, out, ""

    def run(cmd, **kw):
        ran.append(cmd[:3])
        return R(0, "sha256:" + "e" * 64 + "\n")  # the tag exists, bound to an image we never built
    monkeypatch.setattr(B, "_run", run)
    with pytest.raises(B.BuildError, match="not the image hook-repro recorded"):
        B.ensure_image(r, log=lambda *_: None)
    assert ["docker", "build", "--platform"] not in ran


def test_rt_l2_build_context_is_rebuilt_not_trusted(tmp_path, monkeypatch):
    monkeypatch.setattr(B, "CACHE", str(tmp_path))
    r = B.load_recipe("hookc-wce")
    ctx = os.path.join(str(tmp_path), "ctx", r["name"], B.recipe_digest(r)[:16])
    os.makedirs(ctx)
    for n in (".complete", "INJECTED"):
        open(os.path.join(ctx, n), "w").close()
    monkeypatch.setattr(B, "fetch_artifact", lambda a, log=print: "unused")
    monkeypatch.setattr(B, "unpack_artifact", lambda a, src, root: None)
    got, _ = B.prepare_context(r, log=lambda *_: None)
    assert got == ctx and not os.path.exists(os.path.join(ctx, "INJECTED"))


def test_rt_l2_hook_repro_build_version_is_in_the_recipe_digest(monkeypatch):
    r = B.load_recipe("xhc-bin127")
    d0 = B.recipe_digest(r)
    monkeypatch.setattr(B, "BUILD_ABI", "hook-repro-build/999")
    assert B.recipe_digest(r) != d0


def test_rt_o5_builds_on_different_images_are_unverified():
    from test_core import transport_from
    good = rd("claimreward_onledger.wasm")
    ids = iter(["sha256:" + "1" * 64, "sha256:" + "2" * 64])

    def b(src, recipe, params, preset, out_dir):
        return {"recipe": {"digest": "r" * 64}, "image": {"image_id": next(ids)},
                "source": {"tree_sha256": "t" * 64}, "params": {}}, good
    r = V.verify(H_CR, FX, "xhc-bin127", "mainnet", transport=transport_from(recorded()), builder=b, endpoints=MAIN)
    assert r["verdict"] == "UNVERIFIED" and "different images" in r["reason"]


# ---------------- L3: HookName ----------------

@pytest.mark.parametrize("name,ok", [("a", False), ("abcdefghi", False), ("ab", True), ("claimrwd", True),
                                     ("日本", True), ("日" * 9, False)])
def test_rt_l3_hookname_follows_rshooks_2_to_8_chars(name, ok):
    if ok:
        HC.normalize_decls({"name": name})
    else:
        with pytest.raises(HC.HookcError):
            HC.normalize_decls({"name": name})


# ---------------- O1 / O2 / compat ----------------

def test_rt_compat_machine_written_sidecars_round_trip_book_is_hand_formatted():
    import glob
    written = [os.path.join(FX, "rshooks", "recorded_firewall_0.main.metadata.json")] + sorted(
        glob.glob(os.path.join(ROOT, "casestudy", "rshooks", "*", "build*", "hook.metadata.json")))
    assert len(written) == 5
    for p in written:
        with open(p) as f:
            raw = f.read()
        assert HC.dumps(json.loads(raw)) == raw, p
    book = rd("rshooks", "book_accept_all.metadata.json").decode()
    assert HC.dumps(json.loads(book)) != book  # printed in the rshooks book, not written by rshooks-build
    with open(os.path.join(ROOT, "README.md")) as f:
        assert "book_accept_all.metadata.json` is hand-formatted" in " ".join(f.read().split())


def test_rt_o1_o2_readme_states_compatibility_and_trust_model_precisely():
    with open(os.path.join(ROOT, "README.md")) as f:
        t = " ".join(f.read().split())
    assert "same top-level keys and formatting as rshooks sidecars" in t
    assert "readable by rshooks" not in t
    assert '`"chain": null`' in t and "ChainSummary" in t
    assert "Enforced" in t and "Informational" in t
    assert "self-reported" in t and "fingerprint" in t and "same validated ledger" in t


# ---------------- direct guards for the new fail-closed checks (mutation targets) ----------------

def test_guard_fp1_tree_lie_with_real_commit_is_refused(fake, tmp_path):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    assert hookc("build", "--git", r, *TC, "--out", tmp_path / "o") == 0
    d = load(tmp_path / "o" / "0.hook.metadata.json")
    d["source"]["vcs"]["tree"] = "2" * 40
    assert hookc("reproduce", "--metadata", save(tmp_path / "t.json", d), "--git", r, "--platform", "linux/arm64") == 3


def test_guard_export_for_metadata_needs_exactly_one_source(tmp_path):
    meta = {"source": {"vcs": {"commit": "1" * 40, "tree": "2" * 40, "path": ""}}}
    for kw in ({}, {"src": str(tmp_path), "git": str(tmp_path)}):
        with pytest.raises(HC.HookcError, match="exactly one"):
            HC.export_for_metadata(meta, **kw)


def test_guard_corrupt_git_object_refused(tmp_path):
    import zlib
    r = mkrepo(tmp_path / "repo", {"hook.c": b"hello\n"})
    oid = gtxt(r, "rev-parse", "HEAD:hook.c")
    p = r / ".git" / "objects" / oid[:2] / oid[2:]
    os.chmod(p, 0o644)
    p.write_bytes(zlib.compress(b"blob 6\0HELLO\n"))  # git cat-file --batch does not re-hash
    with pytest.raises(HC.HookcError, match="does not hash to its id"):
        HC.export_tree(str(r), "HEAD", "", str(tmp_path / "o"))


def test_guard_dest_path_containment(tmp_path):
    root = os.path.realpath(str(tmp_path / "root"))
    os.makedirs(root)
    for bad in ("../x", "a/../../x"):
        with pytest.raises(HC.HookcError, match="escapes"):
            HC._dest_path(root, bad)
    outside = tmp_path / "outside"
    outside.mkdir()
    os.symlink(str(outside), os.path.join(root, "sub"))
    with pytest.raises(HC.HookcError, match="escapes"):
        HC._dest_path(root, "sub/x")
    assert HC._dest_path(root, "d/e.c") == os.path.join(root, "d", "e.c")


def test_guard_write_new_never_overwrites_or_follows(tmp_path):
    p = str(tmp_path / "f")
    HC._write_new(p, b"a", 0o644)
    with pytest.raises(HC.HookcError):
        HC._write_new(p, b"b", 0o644)
    os.symlink(str(tmp_path / "target"), str(tmp_path / "l"))
    with pytest.raises(HC.HookcError):
        HC._write_new(str(tmp_path / "l"), b"b", 0o644)
    assert open(p, "rb").read() == b"a" and not (tmp_path / "target").exists()


def test_guard_export_relist_must_equal_git(tmp_path, monkeypatch):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    monkeypatch.setattr(HC, "_relist", lambda root: [("hook.c", "0" * 64)])
    with pytest.raises(HC.HookcError, match="differ from"):
        HC.export_tree(str(r), "HEAD", "", str(tmp_path / "o"))


def test_guard_export_destination_must_be_empty(tmp_path):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    (tmp_path / "o").mkdir()
    (tmp_path / "o" / "stale.c").write_bytes(b"x")
    with pytest.raises(HC.HookcError, match="not empty"):
        HC.export_tree(str(r), "HEAD", "", str(tmp_path / "o"))


def test_guard_export_tree_hash_is_computed_from_git_objects(tmp_path):
    r = mkrepo(tmp_path / "repo", {"b.c": b"b\n", "a/z.h": b"z\n"})
    info = HC.export_tree(str(r), "HEAD", "", str(tmp_path / "o"))
    lines = b"".join(p.encode() + b"\0" + hashlib.sha256(d).hexdigest().encode() + b"\n"
                     for p, d in sorted([("a/z.h", b"z\n"), ("b.c", b"b\n")]))
    assert info["tree_sha256"] == hashlib.sha256(lines).hexdigest() and info["file_count"] == 2


def test_guard_double_build_image_and_tree_checks(monkeypatch, tmp_path):
    w = rd("tiny.wasm")
    ms = iter([({"image": {"image_id": "a"}, "source": {"tree_sha256": "t"}}, w),
               ({"image": {"image_id": "b"}, "source": {"tree_sha256": "t"}}, w)])
    monkeypatch.setattr(B, "build", lambda *a, **k: next(ms))
    with pytest.raises(HC.HookcError, match="different images"):
        HC._double_build("s", "r", {}, None, str(tmp_path), None)
    ms2 = iter([({"image": {"image_id": "a"}, "source": {"tree_sha256": "t"}}, w)] * 2)
    monkeypatch.setattr(B, "build", lambda *a, **k: next(ms2))
    with pytest.raises(HC.HookcError, match="not the exported tree"):
        HC._double_build("s", "r", {}, None, str(tmp_path), None, tree_sha256="u")


def test_guard_regenerate_refuses_other_tree():
    with pytest.raises(HC.HookcError, match="not the exported tree"):
        HC.regenerate({}, b"", {"source": {"tree_sha256": "a"}}, {"tree_sha256": "b"})


@pytest.mark.parametrize("change,msg", [
    ({"params": {"CLANG_OPT": "-O2", "WASMOPT": "-O2"}}, "fully resolved"),
    ({"params": {"CLANG_OPT": "-O9", "STAGES": "opt,clean", "WASMOPT": "-O2"}}, "not valid"),
    ({"preset": "no-such-preset"}, "does not resolve"),
])
def test_guard_parse_metadata_params_and_preset(change, msg):
    d = json.loads(rd("hookc", "claimreward_0.hook.metadata.json"))
    d["builder"].update(change)
    with pytest.raises(HC.HookcError, match=msg):
        HC.parse_metadata(d)


def test_guard_verify_hookc_sidecar_requires_regeneration():
    from test_core import fake_builder, transport_from
    good = rd("claimreward_onledger.wasm")
    meta = {"hookhash": H_CR, "doc": {}}
    r = V.verify(H_CR, FX, "xhc-bin127", "mainnet", transport=transport_from(recorded()),
                 builder=fake_builder([good, good]), endpoints=MAIN, metadata=meta)
    assert r["verdict"] == "UNVERIFIED" and "not regenerated" in r["reason"]

    def boom(w, m, built=None):
        raise RuntimeError("docker died")
    r = V.verify(H_CR, FX, "xhc-bin127", "mainnet", transport=transport_from(recorded()),
                 builder=fake_builder([good, good]), endpoints=MAIN, metadata=meta, sidecar=boom)
    assert r["verdict"] == "UNVERIFIED" and "regeneration failed" in r["reason"]


def test_guard_operators_disagreeing_on_definition_fields_is_unverified(fake, tmp_path, monkeypatch):
    r, m = claimreward_sidecar(fake, tmp_path)
    rec = recorded()
    rec[MAIN[1]]["ledger_entry"]["result"]["node"]["Fee"] = "150"
    use_chain(monkeypatch, rec)
    assert verify_cli(r, m, tmp_path / "v") == 3
    assert "cannot check the sidecar" in load(tmp_path / "v" / "verify-report.json")["reason"]


def test_guard_reread_must_return_the_requested_ledger():
    code = rd("tiny.wasm")
    H = sha512half(code)

    def t(url, payload):
        if payload["method"] == "server_info":
            return {"result": {"status": "success", "info": {"pubkey_node": "n9" + url[-5:], "network_id": 21337}}}
        idx = {MAIN[0]: 101, MAIN[1]: 100}[url]  # ignores the requested index
        return {"result": {"status": "success", "validated": True, "ledger_index": idx, "ledger_hash": "%064X" % idx,
                           "node": {"LedgerEntryType": "HookDefinition", "HookHash": H, "CreateCode": code.hex()}}}
    f = F.fetch_createcode(H, "xahau-mainnet", transport=t)
    assert f["ok"] is False and "is not the one requested" in f["reason"] and "common ledger 100" in f["reason"]


def test_guard_reread_failure_is_a_read_failure():
    code = rd("tiny.wasm")
    H = sha512half(code)

    def t(url, payload):
        if payload["method"] == "server_info":
            return {"result": {"status": "success", "info": {"pubkey_node": "n9" + url[-5:], "network_id": 21337}}}
        li = payload["params"][0]["ledger_index"]
        if li != "validated":
            return {"result": {"status": "error", "error": "lgrNotFound"}}
        idx = {MAIN[0]: 101, MAIN[1]: 100}[url]
        return {"result": {"status": "success", "validated": True, "ledger_index": idx, "ledger_hash": "%064X" % idx,
                           "node": {"LedgerEntryType": "HookDefinition", "HookHash": H, "CreateCode": code.hex()}}}
    f = F.fetch_createcode(H, "xahau-mainnet", transport=t)
    assert f["ok"] is False and f["reason"].startswith("read failure at common ledger 100") and "lgrNotFound" in f["reason"]


class _R:
    def __init__(self, rc, out=""):
        self.returncode, self.stdout, self.stderr = rc, out, ""


def test_guard_image_record_must_name_the_tagged_image(tmp_path, monkeypatch):
    monkeypatch.setattr(B, "CACHE", str(tmp_path))
    r = B.load_recipe("hookc-wce")
    dg = B.recipe_digest(r)
    rec = B._image_record_path(r, dg)
    os.makedirs(os.path.dirname(rec))
    with open(rec, "w") as f:
        json.dump({"image_id": "sha256:" + "1" * 64, "recipe_digest": dg}, f)
    monkeypatch.setattr(B, "_run", lambda cmd, **kw: _R(0, "sha256:" + "2" * 64 + "\n"))
    with pytest.raises(B.BuildError, match="not the image hook-repro recorded"):
        B.ensure_image(r, log=lambda *_: None)
    monkeypatch.setattr(B, "_run", lambda cmd, **kw: _R(0, "sha256:" + "1" * 64 + "\n"))
    assert B.ensure_image(r, log=lambda *_: None)["image_id"] == "sha256:" + "1" * 64


def test_guard_image_built_is_recorded_and_inspect_failure_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(B, "CACHE", str(tmp_path))
    r = B.load_recipe("hookc-wce")
    monkeypatch.setattr(B, "prepare_context", lambda recipe, log=print: (str(tmp_path), B.recipe_digest(recipe)))
    state = {"built": False, "id": "sha256:" + "3" * 64}

    def run(cmd, **kw):
        if cmd[1] == "build":
            state["built"] = True
            return _R(0)
        return _R(0, state["id"] + "\n") if state["built"] else _R(1)
    monkeypatch.setattr(B, "_run", run)
    assert B.ensure_image(r, log=lambda *_: None)["image_id"] == state["id"]
    with open(B._image_record_path(r, B.recipe_digest(r))) as f:
        assert json.load(f)["image_id"] == state["id"]
    state.update(built=False)
    state["id"] = ""

    def run2(cmd, **kw):
        if cmd[1] == "build":
            state["built"] = True
            return _R(0)
        return _R(0, "\n") if state["built"] else _R(1)
    monkeypatch.setattr(B, "_run", run2)
    with pytest.raises(B.BuildError, match="inspect"):
        B.ensure_image(r, log=lambda *_: None)


def test_guard_vendor_tree_rehashed_on_use(tmp_path, monkeypatch):
    monkeypatch.setattr(B, "CACHE", str(tmp_path / "cache"))
    src = tmp_path / "src"
    src.mkdir()
    (src / "Cargo.lock").write_text('version = 4\n\n[[package]]\nname = "hook"\nversion = "0.1.0"\n')
    vdir, info = B.prepare_source_vendor(str(src), {}, log=lambda *_: None)
    open(os.path.join(vdir, "INJECTED.rs"), "w").close()
    vdir2, _ = B.prepare_source_vendor(str(src), {}, log=lambda *_: None)
    assert vdir2 == vdir and not os.path.exists(os.path.join(vdir, "INJECTED.rs"))


def test_guard_content_digest_sees_content_mode_and_links(tmp_path):
    (tmp_path / "f").write_bytes(b"a")
    d0 = B.content_digest(str(tmp_path))
    (tmp_path / "f").write_bytes(b"b")
    d1 = B.content_digest(str(tmp_path))
    os.chmod(str(tmp_path / "f"), 0o755)
    d2 = B.content_digest(str(tmp_path))
    os.symlink("f", str(tmp_path / "l"))
    d3 = B.content_digest(str(tmp_path))
    os.unlink(str(tmp_path / "l"))
    os.symlink("g", str(tmp_path / "l"))
    assert len({d0, d1, d2, d3, B.content_digest(str(tmp_path))}) == 5


@pytest.mark.parametrize("kind", ["file", "dir"])
def test_guard_staging_refuses_symlinks(fake, tmp_path, kind):
    d = tmp_path / "s"
    d.mkdir()
    (d / "hook.c").write_bytes(HOOK_C)
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "x.h").write_bytes(b"x")
    if kind == "file":
        os.symlink(str(tmp_path / "outside" / "x.h"), str(d / "x.h"))
    else:
        os.symlink(str(tmp_path / "outside"), str(d / "inc"))
    assert cli.main(["build", str(d), "--recipe", "hookc-llvm22", "--preset", "deploy", "--out", str(tmp_path / "o")]) == 3


def test_guard_staged_source_changed_during_build_refused(fake, tmp_path, monkeypatch):
    d = tmp_path / "s"
    d.mkdir()
    (d / "hook.c").write_bytes(HOOK_C)
    inner = B.run_container

    def racing(recipe, image, src_dir, out_dir, params, timeout=None, vendor_dir=None):
        w = inner(recipe, image, src_dir, out_dir, params)
        with open(os.path.join(src_dir, "hook.c"), "ab") as f:
            f.write(b"// swapped\n")
        return w
    monkeypatch.setattr(B, "run_container", racing)
    with pytest.raises(B.BuildError, match="changed during the build"):
        B.build(str(d), "hookc-llvm22", preset="deploy", out_dir=str(tmp_path / "o"), log=lambda *_: None)


def test_guard_missing_metadata_file_fails_closed(fake, tmp_path):
    assert hookc("reproduce", "--metadata", tmp_path / "nope.json", "--git", tmp_path) == 3


@pytest.mark.parametrize("raw,msg", [
    (b"/abs/x.c", "unsafe path"), (b"a/./b.c", "unsafe path"), (b"a//b.c", "unsafe path"), (b"a/..", "unsafe path"),
    (b"__pycache__/c.h", "reserved"), (b"d/.hook-repro/x", "reserved"), (b".Git/x", "reserved"),
])
def test_guard_safe_tree_name_reasons(raw, msg):
    with pytest.raises(HC.HookcError, match=msg):
        HC.safe_tree_name(raw)
    assert HC.safe_tree_name(b"a/.hidden/b..c") == "a/.hidden/b..c"


def test_guard_dest_path_refuses_before_creating_anything(tmp_path):
    root = os.path.realpath(str(tmp_path / "root"))
    os.makedirs(root)
    with pytest.raises(HC.HookcError, match="escapes"):
        HC._dest_path(root, "a/../../made_outside/x")
    assert not (tmp_path / "made_outside").exists()

"""Regression tests for the 2026-09-29 hostile red-team of hookc / hook-repro (round 4).

Each test is the offline form of one RT round-4 repro script (scratchpad/rt4/f*.sh), driven through
the CLI with docker replaced by the round-1 FAKE CONTAINER (it compiles exactly the directory it is
handed) and, for `verify`, the chain read replaced by a two-operator stub serving the built bytes
(the only simulated part, as in rt4/stub_verify.py). Expectations are literals (exit codes 0/2/3,
verdict strings). Every test named test_rt4_* fails on cd2c3b7 (evidence:
casestudy/hookc/rt-round4/test_rt_round4_on_cd2c3b7.txt); test_guard_* tests pin the fixes' edges.

  F2   `--src WORKTREE` accepted a work tree whose files differ from the blobs built
  F1   xhc-bin127 (clang 15) embedded the wall-clock date via __DATE__/__TIME__/__TIMESTAMP__
  F3   a WCE tool that did not run turned an honest sidecar into MISMATCH (must be UNVERIFIED)
  F3b  a null-WCE sidecar carried a host-specific reason (a local docker image id)
  F4   bind-review dropped the verify report's caveat / operators / re-check flag and network
  H1   git ran with the handed-over repository's own config (filter drivers, includes, ...)
"""
import json
import os

import pytest

from hook_repro import build as B, cli, fetch as F, hookc as HC
from hook_repro.hashing import sha512half

from test_rt_round1 import HOOK_C, fake, git, gtxt, hookc, load, mkrepo, save  # noqa: F401

TC = ["--toolchain", "hookc-llvm22", "--platform", "linux/arm64"]
BAD_C = b'#include "hookapi.h"\nint64_t hook(uint32_t r) { _g(1,1); return rollback(0, 0, 1); }\n'


def chain_stub(monkeypatch, wasm, wce):
    """Two distinct operators serving `wasm` as the validated HookDefinition (Fee/HookCallbackFee
    from WCE, as SetHook writes them)."""
    h = sha512half(wasm)

    def t(url, payload, timeout=20):
        if payload["method"] == "server_info":
            return {"result": {"status": "success", "info": {"pubkey_node": "n9STUB" + url[-8:], "network_id": 21337,
                                                              "build_version": "stub"}}}
        node = {"LedgerEntryType": "HookDefinition", "HookHash": h, "CreateCode": wasm.hex().upper()}
        if wce.get("hook") is not None:
            node["Fee"] = str(wce["hook"])
        if wce.get("cbak"):
            node["HookCallbackFee"] = str(wce["cbak"])
        return {"result": {"status": "success", "validated": True, "ledger_index": 100, "ledger_hash": "AB" * 32,
                           "node": node}}
    monkeypatch.setattr(F, "http_transport", t)
    return h


def built(fake, tmp_path, files=None, name="repo"):
    r = mkrepo(tmp_path / name, files or {"hook.c": HOOK_C})
    assert hookc("build", "--git", r, *TC, "--out", tmp_path / (name + "-o")) == 0
    return r, str(tmp_path / (name + "-o") / "0.hook.metadata.json")


def reproduce_src(m, r):
    return hookc("reproduce", "--metadata", m, "--src", r, "--platform", "linux/arm64")


def verify_src(monkeypatch, m, r, *extra):
    d = load(m)
    with open(os.path.join(os.path.dirname(m), "0.hook.wasm"), "rb") as f:
        h = chain_stub(monkeypatch, f.read(), d["WCE"])
    return cli.main(["verify", "--hookhash", h, "--metadata", m, "--src", str(r), "--platform", "linux/arm64"]
                    + list(extra))


# ---------------- F2: --src work tree must be byte-identical to the blobs built ----------------

def test_rt4_f2_skip_worktree_edit_refused(fake, tmp_path, monkeypatch):
    r, m = built(fake, tmp_path)
    (r / "hook.c").write_bytes(BAD_C)
    git(r, "update-index", "--skip-worktree", "hook.c")
    assert gtxt(r, "status", "--porcelain") == ""  # git status is clean: the edit is hidden
    assert reproduce_src(m, r) == 3
    assert verify_src(monkeypatch, m, r) == 3
    assert hookc("reproduce", "--metadata", m, "--git", r, "--platform", "linux/arm64") == 0  # --git: objects only


def test_rt4_f2_assume_unchanged_edit_refused(fake, tmp_path, monkeypatch):
    r, m = built(fake, tmp_path)
    (r / "hook.c").write_bytes(BAD_C)
    git(r, "update-index", "--assume-unchanged", "hook.c")
    assert gtxt(r, "status", "--porcelain") == ""
    assert reproduce_src(m, r) == 3
    assert verify_src(monkeypatch, m, r) == 3


def test_rt4_f2_visibly_dirty_edit_refused(fake, tmp_path, monkeypatch):
    r, m = built(fake, tmp_path)
    (r / "hook.c").write_bytes(BAD_C)
    assert reproduce_src(m, r) == 3
    assert verify_src(monkeypatch, m, r) == 3


def test_rt4_f2_untracked_file_refused(fake, tmp_path):
    r, m = built(fake, tmp_path)
    (r / "zz_note.c").write_bytes(b"/* not committed */\n")
    assert reproduce_src(m, r) == 3


def test_rt4_f2_ignored_file_refused(fake, tmp_path):
    r, m = built(fake, tmp_path, {"hook.c": HOOK_C, ".gitignore": b"*_local.c\n"})
    (r / "zz_local.c").write_bytes(b"const long long LIMIT = 1000000;\n")
    assert gtxt(r, "status", "--porcelain") == ""
    assert reproduce_src(m, r) == 3


def test_rt4_f2_ignored_file_in_subdir_refused(fake, tmp_path):
    r, m = built(fake, tmp_path, {"hook.c": HOOK_C, ".gitignore": b"__pycache__/\n"})
    (r / "__pycache__").mkdir()
    (r / "__pycache__" / "x.pyc").write_bytes(b"x")
    assert reproduce_src(m, r) == 3


def test_rt4_f2_deleted_file_refused(fake, tmp_path):
    r, m = built(fake, tmp_path, {"hook.c": HOOK_C, "notes.h": b"/* n */\n"})
    (r / "notes.h").unlink()
    git(r, "update-index", "--skip-worktree", "notes.h")
    assert gtxt(r, "status", "--porcelain") == ""
    assert reproduce_src(m, r) == 3


def test_rt4_f2_flag_without_edit_refused(fake, tmp_path):
    """The index flag alone refuses (a later edit would be invisible to git status)."""
    r, m = built(fake, tmp_path)
    git(r, "update-index", "--skip-worktree", "hook.c")
    assert reproduce_src(m, r) == 3
    git(r, "update-index", "--no-skip-worktree", "hook.c")
    git(r, "update-index", "--assume-unchanged", "hook.c")
    assert reproduce_src(m, r) == 3


def test_rt4_f2_subpath_worktree_checked(fake, tmp_path):
    """--path builds: only <path> is compared, and an edit there is refused."""
    r = mkrepo(tmp_path / "repo", {"sub/hook.c": HOOK_C, "README": b"top\n"})
    assert hookc("build", "--git", r, "--path", "sub", *TC, "--out", tmp_path / "o") == 0
    m = str(tmp_path / "o" / "0.hook.metadata.json")
    (r / "README").write_bytes(b"top, edited outside the path\n")
    assert reproduce_src(m, r) == 0
    (r / "sub" / "hook.c").write_bytes(BAD_C)
    git(r, "update-index", "--skip-worktree", "sub/hook.c")
    assert reproduce_src(m, r) == 3


def test_guard_f2_clean_worktree_reproduces(fake, tmp_path, monkeypatch):
    r, m = built(fake, tmp_path, {"hook.c": HOOK_C, "inc/a.h": b"#define A 1\n"})
    (r / "empty").mkdir()  # an empty directory holds no bytes
    assert reproduce_src(m, r) == 0
    assert verify_src(monkeypatch, m, r) == 0


def test_guard_f2_symlink_in_worktree_refused(fake, tmp_path):
    r, m = built(fake, tmp_path)
    os.symlink("hook.c", r / "link.c")
    assert reproduce_src(m, r) == 3


def test_guard_f2_nested_git_dir_refused(fake, tmp_path):
    """Only the toplevel .git is skipped; a .git below it is an extra file."""
    r, m = built(fake, tmp_path)
    (r / "vendor" / ".git").mkdir(parents=True)
    (r / "vendor" / ".git" / "HEAD").write_bytes(b"ref: refs/heads/main\n")
    assert reproduce_src(m, r) == 3


def test_guard_f2_worktree_files_unit(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_bytes(b"x")
    (tmp_path / "a.c").write_bytes(b"a")
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "b.h").write_bytes(b"b")
    got = HC.worktree_files(str(tmp_path), "")
    assert [n for n, _ in got] == ["a.c", "d/b.h"]
    assert [n for n, _ in HC.worktree_files(str(tmp_path), "d")] == ["b.h"]
    with pytest.raises(HC.HookcError):
        HC.check_worktree_matches(str(tmp_path), "", [("a.c", got[0][1])])
    with pytest.raises(HC.HookcError):
        HC.check_worktree_matches(str(tmp_path), "", [("a.c", "0" * 64), ("d/b.h", got[1][1])])
    HC.check_worktree_matches(str(tmp_path), "", got)


def test_guard_f2_symlinked_dir_in_worktree_refused(fake, tmp_path):
    r, m = built(fake, tmp_path)
    (tmp_path / "elsewhere").mkdir()
    (tmp_path / "elsewhere" / "x.h").write_bytes(b"#define X 1\n")
    os.symlink(tmp_path / "elsewhere", r / "inc")
    assert reproduce_src(m, r) == 3


def test_guard_f2_symlinked_path_component_refused(fake, tmp_path):
    r = mkrepo(tmp_path / "repo", {"sub/hook.c": HOOK_C})
    assert hookc("build", "--git", r, "--path", "sub", *TC, "--out", tmp_path / "o") == 0
    m = str(tmp_path / "o" / "0.hook.metadata.json")
    os.rename(r / "sub", tmp_path / "sub_real")
    os.symlink(tmp_path / "sub_real", r / "sub")  # same bytes, but the path is a symlink
    assert reproduce_src(m, r) == 3


# ---------------- F3: a WCE tool that did not run is UNVERIFIED, never MISMATCH ----------------

HOST_REASON = ("WCE tool unavailable: docker tag hook-repro/hookc-wce:7eb3bd03a78f7109 is bound to sha256:"
               "d19813cd80e8ed4f4329229797557ac9015527ba8ba64627614409eaed74ce8f, which is not the image hook-repro "
               "recorded building (None)")


def reproduce_git(m, r, *extra):
    return hookc("reproduce", "--metadata", m, "--git", r, "--platform", "linux/arm64", *extra)


def test_rt4_f3_reproduce_no_wce_is_unverified(fake, tmp_path):
    r, m = built(fake, tmp_path)
    assert load(m)["WCE"] == {"hook": 149, "cbak": 7}
    assert reproduce_git(m, r) == 0
    assert reproduce_git(m, r, "--no-wce") == 3


def test_rt4_f3_wce_tool_unavailable_is_unverified(fake, tmp_path, monkeypatch, capsys):
    r, m = built(fake, tmp_path)
    monkeypatch.setattr(HC, "run_wce", lambda w, log=None: (None, HOST_REASON))
    capsys.readouterr()
    assert reproduce_git(m, r, "--json") == 3
    rep = json.loads(capsys.readouterr().out)
    assert rep["verdict"] == "UNVERIFIED" and "WCE NOT checked" in rep["reason"] and rep["metadata_diff"] == []
    assert verify_src(monkeypatch, m, r) == 3


def test_rt4_f3_no_wce_sidecar_reproduces_with_the_tool(fake, tmp_path):
    """A --no-wce sidecar states no WCE; a verifier whose tool runs regenerates it as null."""
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    assert hookc("build", "--git", r, *TC, "--no-wce", "--out", tmp_path / "o") == 0
    m = str(tmp_path / "o" / "0.hook.metadata.json")
    assert load(m)["WCE"] == {"hook": None, "cbak": None}
    assert reproduce_git(m, r) == 0
    assert reproduce_git(m, r, "--no-wce") == 0


def test_guard_f3_wrong_wce_is_still_mismatch(fake, tmp_path):
    r, m = built(fake, tmp_path)
    d = load(m)
    d["WCE"]["hook"] = 150
    assert reproduce_git(save(tmp_path / "w.json", d), r) == 2


def test_guard_f3_regen_wce_unit():
    doc = {"WCE": {"hook": 1, "cbak": 0}}
    with pytest.raises(HC.WceUnavailable):
        HC.regen_wce(doc, b"", with_wce=False)
    assert HC.regen_wce({"WCE": {"hook": None, "cbak": None}}, b"", with_wce=False) == (None, HC.NO_WCE_REASON)


# ---------------- F3b: no host-specific WCE reason in a sidecar ----------------

def test_rt4_f3b_build_refuses_when_wce_tool_unavailable(fake, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(HC, "run_wce", lambda w, log=None: (None, HOST_REASON))
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    capsys.readouterr()
    assert hookc("build", "--git", r, *TC, "--out", tmp_path / "o") == 3
    assert "WCE tool could not run" in capsys.readouterr().err
    assert not os.path.exists(tmp_path / "o" / "0.hook.metadata.json")


def test_rt4_f3b_sidecar_with_host_reason_refused(fake, tmp_path):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    assert hookc("build", "--git", r, *TC, "--no-wce", "--out", tmp_path / "o") == 0
    d = load(tmp_path / "o" / "0.hook.metadata.json")
    d["builder"]["wce"]["reason"] = HOST_REASON
    assert reproduce_git(save(tmp_path / "h.json", d), r) == 3
    assert reproduce_git(save(tmp_path / "h.json", d), r, "--no-wce") == 3


@pytest.mark.parametrize("wce,reason", [
    ({"hook": None, "cbak": None}, None),
    ({"hook": 149, "cbak": 7}, "WCE not computed (--no-wce)"),
    ({"hook": 149, "cbak": None}, None),
    ({"hook": True, "cbak": 7}, None),
    ({"hook": -1, "cbak": 7}, None),
    ({"hook": 149}, None),
])
def test_rt4_f3b_malformed_wce_block_refused(fake, tmp_path, wce, reason):
    r, m = built(fake, tmp_path)
    d = load(m)
    d["WCE"] = wce
    d["builder"]["wce"]["reason"] = reason
    assert reproduce_git(save(tmp_path / "b.json", d), r) == 3


def test_guard_f3b_no_wce_reason_is_the_fixed_string(fake, tmp_path):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    assert hookc("build", "--git", r, *TC, "--no-wce", "--out", tmp_path / "o") == 0
    assert load(tmp_path / "o" / "0.hook.metadata.json")["builder"]["wce"]["reason"] == "WCE not computed (--no-wce)"


def test_guard_f3b_make_metadata_refuses_reason_mismatch():
    from test_hookc import DECLS_CR, OPT_LOG, PARAMS_CR, meta_doc
    from test_rt_round1 import rd
    w = rd("claimreward_onledger.wasm")
    for wce, why in ((None, "WCE tool unavailable: x"), ({"hook": 1, "cbak": 0}, "x"), (None, None)):
        with pytest.raises(HC.HookcError):
            HC.make_metadata(DECLS_CR, w, wce, why, "xhc-bin127", "classic", PARAMS_CR, OPT_LOG, meta_doc()["source"],
                             ["linux/amd64"])


# ---------------- F4: bind-review carries what qualifies the verdict; network must match ----------------

H_OTHER = "0123456789ABCDEF" * 4  # synthetic HookHash of a testnet hook
REPORT_1OP = {"verdict": "REPRODUCED", "hookhash": H_OTHER, "network": "xahau-testnet", "recipe": "kvt-llvm22-amd64",
              "distinct_operators": 1, "caveat": "single-operator read accepted by --allow-single-operator",
              "platforms_built_rechecked": True, "platforms_rebuilt": ["linux/amd64", "linux/arm64"],
              "builds": [{"recipe_digest": "d" * 64, "source_tree_sha256": "s" * 64}]}


def bind_cli(tmp_path, report, *extra):
    rv = tmp_path / "review.md"
    rv.write_text("Reviewed HookHash %s.\n" % H_OTHER)
    rp = save(tmp_path / "verify-report.json", report)
    out = tmp_path / "binding.json"
    rc = cli.main(["bind-review", str(rv), "--hookhash", H_OTHER, "--verify-report", rp, "--out", str(out)] + list(extra))
    return rc, (load(out) if out.exists() else None)


def test_rt4_f4_single_operator_caveat_carried(tmp_path):
    rc, b = bind_cli(tmp_path, REPORT_1OP, "--network", "xahau-testnet")
    assert rc == 0 and b["problems"] == []
    vr = b["verify_report"]
    assert vr["caveat"] == "single-operator read accepted by --allow-single-operator"
    assert vr["distinct_operators"] == 1 and vr["network"] == "xahau-testnet"
    assert b["caveats"] == ["verify report caveat: single-operator read accepted by --allow-single-operator",
                            "chain read from 1 distinct operator(s), not two"]


def test_rt4_f4_platforms_not_rechecked_carried(tmp_path):
    rep = dict(REPORT_1OP, distinct_operators=2, caveat=None, platforms_built_rechecked=False,
               platforms_rebuilt=["linux/amd64"])
    rc, b = bind_cli(tmp_path, rep, "--network", "xahau-testnet")
    assert rc == 0 and b["verify_report"]["platforms_built_rechecked"] is False
    assert b["verify_report"]["platforms_rebuilt"] == ["linux/amd64"]
    assert b["caveats"] == ["builder.platforms_built NOT re-checked (rebuilt only linux/amd64)"]


def test_rt4_f4_network_mismatch_refused(tmp_path):
    rc, b = bind_cli(tmp_path, REPORT_1OP, "--network", "xahau-mainnet")
    assert rc == 3 and b is None


def test_guard_f4_network_taken_from_report(tmp_path):
    rc, b = bind_cli(tmp_path, dict(REPORT_1OP, distinct_operators=2, caveat=None))
    assert rc == 0 and b["network"] == "xahau-testnet" and b["caveats"] == [] and b["problems"] == []


def test_guard_f4_operator_count_edges():
    from hook_repro.bind import report_caveats
    assert report_caveats({"distinct_operators": 3}) == []
    assert report_caveats({"distinct_operators": True}) == ["chain read from True distinct operator(s), not two"]
    assert report_caveats({}) == ["chain read from None distinct operator(s), not two"]


# ---------------- H1: git never runs with the handed-over repository's own risky config ----------------

def hostile_filter_repo(tmp_path, via_include=False):
    """A committed repo whose LOCAL config defines a clean filter that runs a command, assigned
    to every path by $GIT_DIR/info/attributes; hook.c's mtime changes so `git status` must
    re-read it through the filter."""
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    marker = tmp_path / "MARKER"
    cmd = "touch '%s'; cat" % marker
    if via_include:
        inc = tmp_path / "inc.cfg"
        inc.write_text('[filter "evil"]\n\tclean = %s\n' % cmd)
        git(r, "config", "include.path", str(inc))
    else:
        git(r, "config", "filter.evil.clean", cmd)
    (r / ".git" / "info").mkdir(exist_ok=True)
    (r / ".git" / "info" / "attributes").write_text("* filter=evil\n")
    os.utime(r / "hook.c", (1_000_000_000, 1_000_000_000))
    return r, marker


def test_rt4_h1_repo_filter_driver_never_runs(fake, tmp_path):
    r, marker = hostile_filter_repo(tmp_path)
    assert hookc("build", r, *TC, "--out", tmp_path / "o") == 3
    assert not marker.exists()


def test_rt4_h1_included_filter_driver_never_runs(fake, tmp_path):
    r, marker = hostile_filter_repo(tmp_path, via_include=True)
    assert hookc("build", r, *TC, "--out", tmp_path / "o") == 3
    assert not marker.exists()


def test_rt4_h1_risky_repo_config_refused(fake, tmp_path):
    for key, val in (("filter.x.smudge", "cat"), ("include.path", "/dev/null"), ("includeIf.gitdir:/.path", "/x"),
                     ("core.worktree", str(tmp_path))):
        r = mkrepo(tmp_path / ("r" + str(abs(hash(key)))), {"hook.c": HOOK_C})
        git(r, "config", key, val)
        assert hookc("build", "--git", r, *TC, "--out", tmp_path / "o") == 3, key
        assert hookc("build", r, *TC, "--out", tmp_path / "o") == 3, key
        with pytest.raises(HC.HookcError):
            HC.git_config_check(str(r))


def test_guard_h1_ordinary_clone_config_accepted(fake, tmp_path):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    for k, v in (("remote.origin.url", "https://example.invalid/x.git"), ("branch.main.remote", "origin"),
                 ("core.fsmonitor", "true"), ("core.attributesFile", "/nonexistent")):
        git(r, "config", k, v)
    HC.git_config_check(str(r))
    assert hookc("build", r, *TC, "--out", tmp_path / "o") == 0


def test_guard_h1_git_cmd_overrides():
    c = HC.git_cmd("r", "x")
    for kv in ("core.fsmonitor=false", "core.attributesFile=/dev/null", "core.useReplaceRefs=false"):
        assert kv in c and c[c.index(kv) - 1] == "-c"


# ---------------- F1: no C toolchain embeds the build's date or time ----------------

# What clang >= 16 expands under SOURCE_DATE_EPOCH=0 (hookc-llvm22, observed:
# casestudy/hookc/rt-round4/f1_date_macros_*.txt); clang 15 (xhc-bin127) ignores SOURCE_DATE_EPOCH.
EPOCH0_DEFINES = ['-D__DATE__="Jan  1 1970"', '-D__TIME__="00:00:00"', '-D__TIMESTAMP__="Thu Jan  1 00:00:00 1970"']
RECORD_CLANG = ('[ "${1:-}" = --version ] && { echo "clang version fake"; exit 0; }\n'
                'printf "%s\\0" "$@" > "$FAKE_LOG_DIR/clang.args"; echo "SDE=${SOURCE_DATE_EPOCH:-unset}" '
                '> "$FAKE_LOG_DIR/clang.env"\n'
                'o=; n=; for a in "$@"; do [ "$n" = 1 ] && o=$a; n=; [ "$a" = -o ] && n=1; done\n'
                'printf "WASM\\n" > "$o"\n')


def clang_run(recipe, tmp_path, monkeypatch):
    import test_rt_round3 as R3
    monkeypatch.setitem(R3.FAKE_TOOLS, "clang", RECORD_CLANG)
    rc, log, _ = R3.run_pipeline(recipe, tmp_path, {"hook.c": b"int x;\n"}, CLANG_OPT="-O2", WASMOPT="-O2",
                                 STAGES="opt,clean")
    root = tmp_path / "root"
    args = (root / "clang.args").read_bytes().split(b"\0")[:-1]
    return rc, log, [a.decode() for a in args], (root / "clang.env").read_text().strip()


def test_rt4_f1_xhc_bin127_defines_the_date_macros(tmp_path, monkeypatch):
    rc, log, args, env = clang_run("xhc-bin127", tmp_path, monkeypatch)
    assert rc == 0
    assert args[:4] == ["-Wno-builtin-macro-redefined"] + EPOCH0_DEFINES  # four separate argv words, first
    assert args[args.index("--") + 1:] == ["hook.c"]
    assert all(d in HC._log_commands(log)[0] for d in EPOCH0_DEFINES)  # recorded in builder.commands


@pytest.mark.parametrize("recipe", ["hookc-llvm22", "hookc-llvm22-amd64", "kvt-llvm22", "kvt-llvm22-amd64"])
def test_guard_f1_llvm22_pipelines_run_clang_with_source_date_epoch_0(recipe, tmp_path, monkeypatch):
    rc, _, args, env = clang_run(recipe, tmp_path, monkeypatch)
    assert rc == 0 and env == "SDE=0" and not any(a.startswith("-D__DATE__") for a in args)


# ---------------- RT5 H-a: --src must be the repo root or the sidecar's own source dir ----------------

def test_rt5_ha_src_other_directory_refused(fake, tmp_path, monkeypatch):
    r, m = built(fake, tmp_path, files={"hook.c": HOOK_C, "other/readme.c": b"/* not the hook */\n"})
    assert load(m)["source"]["vcs"]["path"] == ""
    assert reproduce_src(m, r / "other") == 3
    assert verify_src(monkeypatch, m, r / "other") == 3


def test_rt5_ha_src_repo_root_still_reproduces(fake, tmp_path):
    r, m = built(fake, tmp_path, files={"hook.c": HOOK_C, "other/readme.c": b"/* not the hook */\n"})
    assert reproduce_src(m, r) == 0


def test_rt5_src_head_moved_but_files_restored_refused(fake, tmp_path):
    # the work tree bytes equal the sidecar's blobs, but HEAD:<path> is another TREE: the check is
    # tree-level (HEAD:<path> must be the sidecar's source.vcs.tree), not commit-level; a HEAD that
    # is another commit with the same tree at <path> is accepted and the export of the sidecar's
    # own commit is built -> here refused, not REPRODUCED
    r, m = built(fake, tmp_path)
    (r / "hook.c").write_bytes(BAD_C)
    git(r, "commit", "-qam", "move HEAD")
    (r / "hook.c").write_bytes(HOOK_C)
    assert reproduce_src(m, r) == 3

"""hookc --select: one top-level .c from a directory that holds several, for toolchains that
compile every top-level .c (buildbox-2026-10, xhc-bin127). The recipes are NOT changed: hookc
withholds the other top-level .c files from the container, and records that in the sidecar
(source.entry + source.entry_selector).

Expected values are LITERALS from outside the package:
  - tree hashes SEL_FULL / SEL_COMPILED: `find . -type f | sort | printf 'path\\0sha256\\n' |
    shasum -a 256` over the SEL_FILES tree (all files / without b.c and c.c), run in a shell;
  - HandyHooks sizes, sha256 and HookHashes: the 2026-10-06 builder-hooks census
    (~/kvt-evidence/builder-hooks-candidates-2026-10-06/results.jsonl), which built each .c
    ALONE in a directory with plain `hook-repro build`, before hookc had --select;
  - HandyHooks source and template-header sha256: census sources.tsv and the gist copy there;
  - ClaimReward: the recorded sidecar casestudy/hookc/claimreward/0.hook.metadata.json.

Docker rebuilds are opt-in (HOOK_REPRO_DOCKER_TESTS=1) and need local clones:
  HANDYHOOKS_REPO   a clone of github.com/Handy4ndy/HandyHooks holding commit e5480f9be35c
  HOOKC_TEMPLATE_HEADERS  dir with the IDE template headers (gist 028e8ce6..., rev 1c9cb1cc)
  CLAIMREWARD_REPO  a clone of github.com/Ekiserrepe/cron-claimreward-xahau (regression)
"""
import hashlib
import json
import os
import shutil
import subprocess

import pytest

from hook_repro import build as B, cli, hookc as HC

from test_hookc import FX, HX, TREE_FX, fx_repo, git, rd, stub, write_meta

ROOT = os.path.join(os.path.dirname(__file__), "..")
SEL_FILES = {
    "a.c": b"int64_t hook(uint32_t r){return 0;}\n",
    "b.c": b"int64_t hook(uint32_t r){return 1;}\n",
    "c.c": b"int64_t hook(uint32_t r){return 2;}\n",
    "inc.h": b"#define X 1\n",
    "sub/d.c": b"not compiled\n",
    "README": b"readme\n",
}
SEL_FULL = "53b24bb9efabe22c0d0db2822d7b207e662a7e1a50a44d9e7c85f8087e26303f"
SEL_COMPILED = "ca0df8435791f6295ab8b3b71f7e237a83f630146190fe29ba82dee20469fa36"  # a.c inc.h README sub/d.c


def mk_sel_dir(root):
    for n, data in SEL_FILES.items():
        p = os.path.join(str(root), *n.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
    return str(root)


def mk_sel_repo(tmp_path):
    r = tmp_path / "selrepo"
    mk_sel_dir(r / "hooks")
    git(tmp_path, "init", "-q", str(r))
    git(r, "add", *("hooks/" + n for n in SEL_FILES))
    git(r, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "sel")
    return str(r)


def seen_stub(monkeypatch, wasm):
    """stub() that also records the files each fake container received."""
    seen = []
    stub(monkeypatch, [wasm] * 8)
    inner = B.build

    def fake(src, recipe, params, preset, out_dir, log=None):
        seen.append(sorted(e[0] for e in HC.tree_hash(src)[1]))
        # the real build.build resolves params against the recipe (defaults + preset)
        return inner(src, recipe, B.resolve_params(B.load_recipe(recipe), params, preset), preset, out_dir, log)
    monkeypatch.setattr(B, "build", fake)
    return seen


# ---------------- the selector name ----------------

@pytest.mark.parametrize("bad,msg", [
    ("../Rewards.c", "path traversal"), ("a/../b.c", "path traversal"), ("..\\x.c", "path traversal"),
    ("/etc/x.c", "absolute path"), ("\\x.c", "absolute path"),
    ("sub/d.c", "names a path, not a top-level file"), ("./a.c", "names a path"),
    ("a.h", "is not a .c file"), ("a.c.txt", "is not a .c file"), ("a.C", "is not a .c file"),
    ("-x.c", "not a plain .c file name"), (".x.c", "not a plain .c file name"), ("a b.c", "not a plain .c file name"),
    ("", "give the name of one top-level .c file"),
])
def test_select_name_refused(bad, msg):
    with pytest.raises(HC.HookcError, match=msg.replace(".", r"\.").replace("(", r"\(")):
        HC.check_select("buildbox-2026-10", bad)


def test_select_only_for_toolchains_without_entry_param():
    assert HC.check_select("buildbox-2026-10", "Rewards.c") == "Rewards.c"
    assert HC.check_select("xhc-bin127", "Rewards.c") == "Rewards.c"
    assert HC.check_select("kvt-llvm22", None) is None
    for tc in ("kvt-llvm22", "hookc-llvm22"):
        with pytest.raises(HC.HookcError, match="use --entry"):
            HC.check_select(tc, "a.c")
    # --entry keeps its old meaning and its old refusal on entry-less toolchains (unchanged)
    with pytest.raises(HC.HookcError, match="it has no entry selector"):
        HC.params_for("buildbox-2026-10", "a.c", {})


# ---------------- staging ----------------

def test_stage_selected_withholds_only_other_top_level_c(tmp_path):
    src = mk_sel_dir(tmp_path / "src")
    sel = HC.stage_selected(src, "a.c", str(tmp_path / "staged"))
    assert sel == {"entry": "a.c", "withheld": ["b.c", "c.c"], "tree_sha256": SEL_COMPILED, "file_count": 4}
    got = sorted(os.path.relpath(os.path.join(d, f), str(tmp_path / "staged"))
                 for d, _, fs in os.walk(str(tmp_path / "staged")) for f in fs)
    assert got == ["README", "a.c", "inc.h", os.path.join("sub", "d.c")]
    for n in ("a.c", "inc.h", "README", "sub/d.c"):  # passed byte for byte
        assert (tmp_path / "staged" / n).read_bytes() == SEL_FILES[n]
    assert sorted(os.listdir(src)) == ["README", "a.c", "b.c", "c.c", "inc.h", "sub"]  # source untouched
    assert HC.tree_hash(src)[0] == SEL_FULL


def test_stage_selected_refuses_missing_symlink_and_non_file(tmp_path):
    src = mk_sel_dir(tmp_path / "src")
    with pytest.raises(HC.HookcError, match="no such file at the top level"):
        HC.stage_selected(src, "zz.c", str(tmp_path / "s1"))
    os.symlink("a.c", os.path.join(src, "l.c"))
    with pytest.raises(HC.HookcError, match="is a symlink"):
        HC.stage_selected(src, "l.c", str(tmp_path / "s2"))
    os.remove(os.path.join(src, "l.c"))
    outside = tmp_path / "outside.c"
    outside.write_bytes(b"int secret;\n")
    os.symlink(str(outside), os.path.join(src, "out.c"))
    with pytest.raises(HC.HookcError, match="is a symlink"):
        HC.stage_selected(src, "out.c", str(tmp_path / "s3"))
    # a symlink elsewhere in the tree (out of the dir) is refused too, even when the entry is fine
    with pytest.raises(B.BuildError, match="not a regular file|symlink"):
        HC.stage_selected(src, "a.c", str(tmp_path / "s4"))
    os.remove(os.path.join(src, "out.c"))
    os.mkdir(os.path.join(src, "dir.c"))
    with pytest.raises(HC.HookcError, match="is not a regular file"):
        HC.stage_selected(src, "dir.c", str(tmp_path / "s5"))


def test_stage_selected_keeps_a_directory_named_dot_c(tmp_path):
    # the pipelines compile `find . -maxdepth 1 -type f -name '*.c'`: a directory lib.c is not a source
    src = mk_sel_dir(tmp_path / "src")
    os.makedirs(os.path.join(src, "lib.c"))
    with open(os.path.join(src, "lib.c", "x.h"), "wb") as f:
        f.write(b"#define Y 2\n")
    sel = HC.stage_selected(src, "a.c", str(tmp_path / "staged"))
    assert sel["withheld"] == ["b.c", "c.c"] and (tmp_path / "staged" / "lib.c" / "x.h").read_bytes() == b"#define Y 2\n"


def test_unchanged_buildbox_pipeline_compiles_only_the_selected_file(tmp_path, monkeypatch):
    # the REAL buildbox-2026-10 pipeline.sh (fake tools): its own log line "sources: ..." is what
    # clang got after `--`
    import test_rt_round3 as R3
    from test_buildbox import DRIVER_CLANG
    monkeypatch.setitem(R3.FAKE_TOOLS, "clang", DRIVER_CLANG + R3.FAKE_TOOLS["clang"])
    flat = {n: d for n, d in SEL_FILES.items() if "/" not in n}
    src = tmp_path / "src"
    src.mkdir()
    for n, d in flat.items():
        (src / n).write_bytes(d)
    HC.stage_selected(str(src), "b.c", str(tmp_path / "staged"))
    staged = {n: (tmp_path / "staged" / n).read_bytes() for n in os.listdir(str(tmp_path / "staged"))}
    env = dict(CLANG_OPT="-O3", WASMOPT="builder2025", STAGES="opt,clean")
    rc, log, _ = R3.run_pipeline("buildbox-2026-10", tmp_path / "p1", staged, **env)
    assert rc == 0 and "sources: b.c\n" in log
    rc, log, _ = R3.run_pipeline("buildbox-2026-10", tmp_path / "p2", flat, **env)  # no selector: every .c
    assert rc == 0 and "sources: a.c b.c c.c\n" in log


# ---------------- build: what the container gets, what the sidecar records ----------------

def test_build_with_select_records_the_entry_and_withholds_the_rest(tmp_path, monkeypatch):
    w = rd(FX, "claimreward_onledger.wasm")
    seen = seen_stub(monkeypatch, w)
    r = mk_sel_repo(tmp_path)
    meta, _, summ = HC.build(git=r, path="hooks", tc_name="buildbox-2026-10", select="c.c", out_dir=str(tmp_path / "o"))
    assert seen == [["README", "c.c", "inc.h", "sub/d.c"]] * 2  # both builds, only the entry's .c
    s = meta["source"]
    assert list(s) == ["vcs", "tree_sha256", "file_count", "entry", "entry_selector"]
    assert s["vcs"]["tree"] == git(r, "rev-parse", "HEAD:hooks") and s["vcs"]["path"] == "hooks"
    assert s["tree_sha256"] == SEL_FULL and s["file_count"] == 6 and s["entry"] == "c.c"
    # compiled_tree_sha256 for a.c is the literal SEL_COMPILED (next test); here only its shape
    assert {k: v for k, v in s["entry_selector"].items() if k != "compiled_tree_sha256"} == {
        "by": "hookc", "mode": "withhold-other-top-level-c", "withheld": ["a.c", "b.c"], "compiled_file_count": 4}
    assert HC.SHA_RE.match(s["entry_selector"]["compiled_tree_sha256"])
    assert s["entry_selector"]["compiled_tree_sha256"] not in (SEL_FULL, SEL_COMPILED)
    assert meta["builder"]["params"] == {"CLANG_OPT": "-O3", "STAGES": "opt,clean", "WASMOPT": "builder2025"}
    assert "ENTRY" not in meta["builder"]["params"]  # the recipe's params are untouched
    assert summ["source"] == s
    on_disk = json.loads((tmp_path / "o" / "0.hook.metadata.json").read_text())
    assert on_disk["source"] == s
    assert HC.parse_metadata(on_disk)["source"]["entry"] == "c.c"


def test_build_with_select_a_c_records_the_literal_compiled_tree(tmp_path, monkeypatch):
    seen_stub(monkeypatch, rd(FX, "claimreward_onledger.wasm"))
    r = mk_sel_repo(tmp_path)
    meta, _, _ = HC.build(git=r, path="hooks", tc_name="xhc-bin127", select="a.c", out_dir=str(tmp_path / "o"))
    assert meta["source"]["entry_selector"]["compiled_tree_sha256"] == SEL_COMPILED


@pytest.mark.parametrize("bad,msg", [("../selrepo/hooks/a.c", "path traversal"), ("zz.c", "no such file"),
                                     ("inc.h", "not a .c file"), ("sub/d.c", "names a path"),
                                     ("/etc/passwd.c", "absolute path")])
def test_build_select_refused_before_any_container(tmp_path, monkeypatch, bad, msg):
    seen = seen_stub(monkeypatch, rd(FX, "claimreward_onledger.wasm"))
    r = mk_sel_repo(tmp_path)
    with pytest.raises(HC.HookcError, match=msg):
        HC.build(git=r, path="hooks", tc_name="buildbox-2026-10", select=bad, out_dir=str(tmp_path / "o"))
    assert seen == [] and not os.path.exists(str(tmp_path / "o" / "0.hook.metadata.json"))


@pytest.mark.parametrize("bad,msg", [("../x.c", "path traversal"), ("missing.c", "no such file"),
                                     ("inc.h", "not a .c file"), ("sub/d.c", "names a path")])
def test_cli_select_refused_nonzero_exit(tmp_path, monkeypatch, capsys, bad, msg):
    seen = seen_stub(monkeypatch, rd(FX, "claimreward_onledger.wasm"))
    monkeypatch.setattr(B, "docker_available", lambda: True)
    r = mk_sel_repo(tmp_path)
    rc = cli.main(["hookc", "build", "--git", r, "--path", "hooks", "--toolchain", "buildbox-2026-10",
                   "--select", bad, "--no-wce", "--out", str(tmp_path / "o")])
    assert rc == 3 and msg in capsys.readouterr().err and seen == []


def test_unversioned_select(tmp_path, monkeypatch):
    seen = seen_stub(monkeypatch, rd(FX, "claimreward_onledger.wasm"))
    src = mk_sel_dir(tmp_path / "plain")
    meta, _, _ = HC.build(src=src, tc_name="buildbox-2026-10", select="a.c", allow_unversioned=True,
                          out_dir=str(tmp_path / "o"))
    assert seen[0] == ["README", "a.c", "inc.h", "sub/d.c"]
    assert meta["source"]["vcs"] is None and meta["source"]["tree_sha256"] == SEL_FULL
    assert meta["source"]["entry"] == "a.c" and meta["source"]["entry_selector"]["compiled_tree_sha256"] == SEL_COMPILED
    assert sorted(os.listdir(src)) == ["README", "a.c", "b.c", "c.c", "inc.h", "sub"]


# ---------------- no selector: byte-identical to before ----------------

def test_no_select_sidecar_is_the_recorded_format_byte_for_byte(tmp_path, monkeypatch):
    """Without --select, build() writes exactly the recorded ClaimReward sidecar (only `source`
    differs: it is the fixture repo's, with the literal TREE_FX), and no entry_selector key."""
    w = rd(FX, "claimreward_onledger.wasm")
    seen = seen_stub(monkeypatch, w)
    repo, sb = fx_repo(tmp_path)
    decls = HC.normalize_decls({"on": ["Cron"], "can_emit": ["ClaimReward"]})[0]
    meta, _, summ = HC.build(git=repo, tc_name="xhc-bin127", preset="classic", decls=decls, out_dir=str(tmp_path / "o"))
    want = json.loads(rd(HX, "claimreward_0.hook.metadata.json"))
    want["source"] = sb
    assert (tmp_path / "o" / "0.hook.metadata.json").read_text() == HC.dumps(want)
    assert "entry_selector" not in meta["source"] and summ["source"] == sb
    assert seen == [sorted(e[0] for e in HC.tree_hash(os.path.join(FX, "tree"))[1])] * 2  # every file, as before
    assert HC.source_block(None, {"vcs": sb["vcs"], "tree_sha256": TREE_FX, "file_count": 4}, None) == sb


# ---------------- sidecar parse ----------------

def sel_doc():
    d = json.loads(rd(HX, "claimreward_0.hook.metadata.json"))  # xhc-bin127: no entry parameter
    d["source"] = dict(d["source"], entry="Rewards.c", entry_selector={
        "by": "hookc", "mode": "withhold-other-top-level-c", "withheld": ["IDOMulti.c", "Router.c"],
        "compiled_tree_sha256": SEL_COMPILED, "compiled_file_count": 2})
    return d


def test_parse_metadata_accepts_selector():
    assert HC.parse_metadata(sel_doc())["source"]["entry"] == "Rewards.c"


@pytest.mark.parametrize("mut,msg", [
    (lambda s: s.pop("entry_selector"), "not the entry the params compile"),
    (lambda s: s.update(entry_selector=None), "exactly the keys"),
    (lambda s: s["entry_selector"].pop("withheld"), "exactly the keys"),
    (lambda s: s["entry_selector"].update(extra=1), "exactly the keys"),
    (lambda s: s["entry_selector"].update(by="other"), "by/mode"),
    (lambda s: s["entry_selector"].update(mode="all"), "by/mode"),
    (lambda s: s.update(entry=None), "without source.entry"),
    (lambda s: s.update(entry="x.h"), "not a .c file name"),
    (lambda s: s["entry_selector"].update(withheld=["Router.c", "IDOMulti.c"]), "sorted list"),
    (lambda s: s["entry_selector"].update(withheld=["Rewards.c"]), "sorted list"),
    (lambda s: s["entry_selector"].update(withheld=["sub/x.c"]), "sorted list"),
    (lambda s: s["entry_selector"].update(withheld=["a.h"]), "sorted list"),
    (lambda s: s["entry_selector"].update(withheld="Router.c"), "sorted list"),
    (lambda s: s["entry_selector"].update(compiled_tree_sha256="00"), "compiled_tree_sha256"),
    (lambda s: s["entry_selector"].update(compiled_file_count=0), "positive integer"),
    (lambda s: s["entry_selector"].update(compiled_file_count=True), "positive integer"),
])
def test_parse_metadata_refuses_bad_selector(mut, msg):
    d = sel_doc()
    mut(d["source"])
    with pytest.raises(HC.HookcError, match=msg):
        HC.parse_metadata(d)


def test_parse_metadata_refuses_selector_on_entry_param_toolchain():
    d = json.loads(rd(ROOT, "casestudy", "hookc", "claimreward-llvm22", "0.hook.metadata.json"))
    d["source"]["entry_selector"] = sel_doc()["source"]["entry_selector"]
    with pytest.raises(HC.HookcError, match="has an entry parameter"):
        HC.parse_metadata(d)


# ---------------- reproduce / verify a --select sidecar ----------------

def built_sel(tmp_path, monkeypatch, select="b.c"):
    w = rd(FX, "claimreward_onledger.wasm")
    seen = seen_stub(monkeypatch, w)
    r = mk_sel_repo(tmp_path)
    HC.build(git=r, path="hooks", tc_name="buildbox-2026-10", select=select, out_dir=str(tmp_path / "o"))
    return r, str(tmp_path / "o" / "0.hook.metadata.json"), seen


def test_reproduce_select_round_trip(tmp_path, monkeypatch):
    r, m, seen = built_sel(tmp_path, monkeypatch)
    rep = HC.reproduce(m, git=r, out_dir=str(tmp_path / "rep"))
    assert rep["verdict"] == "REPRODUCED", rep["reason"]
    assert seen[2:] == [["README", "b.c", "inc.h", "sub/d.c"]] * 2  # the rebuild got the same selection
    assert rep["rebuilt"]["source"]["entry_selector"]["withheld"] == ["a.c", "c.c"]


def test_reproduce_select_from_work_tree(tmp_path, monkeypatch):
    r, m, _ = built_sel(tmp_path, monkeypatch)
    assert HC.reproduce(m, src=os.path.join(r, "hooks"), out_dir=str(tmp_path / "rep"))["verdict"] == "REPRODUCED"


@pytest.mark.parametrize("mut", [
    lambda s: s["entry_selector"].update(withheld=["a.c"]),
    lambda s: s["entry_selector"].update(compiled_tree_sha256="0" * 64),
    lambda s: s["entry_selector"].update(compiled_file_count=5),
    lambda s: s.update(entry="a.c", entry_selector=dict(s["entry_selector"], withheld=["b.c", "c.c"])),
])
def test_reproduce_select_tamper_is_mismatch(tmp_path, monkeypatch, mut):
    r, m, _ = built_sel(tmp_path, monkeypatch)
    d = json.loads(open(m).read())
    mut(d["source"])
    rep = HC.reproduce(write_meta(tmp_path, d, "t.json"), git=r, out_dir=str(tmp_path / "rep"))
    assert rep["verdict"] == "MISMATCH" and any(p.startswith("source.") for p in rep["metadata_diff"])


def test_reproduce_select_container_tree_checked(tmp_path, monkeypatch):
    r, m, _ = built_sel(tmp_path, monkeypatch)
    inner = B.build

    def full_tree(src, recipe, params, preset, out_dir, log=None):  # a container that got another tree
        mm, w = inner(src, recipe, params, preset, out_dir, log)
        mm["source"]["tree_sha256"] = SEL_FULL
        return mm, w
    monkeypatch.setattr(B, "build", full_tree)
    with pytest.raises(HC.HookcError, match="not the exported tree"):
        HC.reproduce(m, git=r, out_dir=str(tmp_path / "rep"))


def test_reproduce_select_entry_missing_in_commit_refused(tmp_path, monkeypatch):
    r, m, _ = built_sel(tmp_path, monkeypatch)
    d = json.loads(open(m).read())
    d["source"]["entry"] = "zz.c"
    with pytest.raises(HC.HookcError, match="no such file"):
        HC.reproduce(write_meta(tmp_path, d, "t.json"), git=r, out_dir=str(tmp_path / "rep"))


def test_verify_metadata_select_rebuilds_the_selection(tmp_path, monkeypatch):
    r, m, seen = built_sel(tmp_path, monkeypatch)
    meta = HC.load_metadata_file(m)
    src_dir, info, cleanup = HC.export_for_metadata(meta, git=r)
    try:
        assert sorted(e[0] for e in HC.tree_hash(src_dir)[1]) == ["README", "b.c", "inc.h", "sub/d.c"]
        assert info["tree_sha256"] == SEL_FULL and HC.compiled_tree(info) == info["selection"]["tree_sha256"]
    finally:
        shutil.rmtree(cleanup, ignore_errors=True)


# ---------------- docker: HandyHooks IssuanceHookset/Fin against the census ----------------

HH_COMMIT = "e5480f9be35c0b041c322a20443c199efbbe0116"
HH_PATH = "IssuanceHookset/Fin"
HH_SRC_SHA256 = {  # census sources.tsv
    "Rewards.c": "3460abefe59f88ecdbe748191f58f40b212fb2588b8eafea25dfd831d91b973c",
    "Router.c": "63aec48d96f2f60591c1380c1cfa9355ba52a09de114a07ccb94c4a5dcb95b67",
    "IDOMulti.c": "4b843bdd76cf0f9c7a61dace20218c7bd3706aac4fd8d955702cd59a5c6228e2",
}
TEMPLATE_SHA256 = {  # IDE template headers, gist 028e8ce6d6d674776970caf8acc77ecc rev 1c9cb1cc
    "date.h": "57f8fcd8d4aaa60b7c0f4f3d2a67324ff43e79d8e453b511367b65d18cdc03ec",
    "error.h": "db8d4095ea21c08e50acb773e2c5d17efb02adec193440e5a214420884d83497",
    "extern.h": "13d3b9fa7e2571bc3ee316415a63b5f17a21d0691ff3341c5b294c098d5e9693",
    "hookapi.h": "a19a4ecc25ec4d1ac27d9434e612a89b8466124b604f0836be9a6a638e785161",  # public header sha256 gitleaks:allow
    "macro.h": "d6f77700ca9dfc9d5d8efa14c3e3dab4903874c657b0cdf7d1bc8c4ccf5bfed6",
    "sfcodes.h": "8ba19c0a160ff0894259ee129e63b23e457675fc82829467f0a48be27d865f14",
}
CENSUS = {  # name: (headers, size, sha256, HookHash) from census results.jsonl (rows 31-33)
    "Rewards.c": ("stock", 4950, "b79258129e2869f9ce287b4813c2089ac95f3f97fb96087691e8cb4c65d50e12",
                  "8CFC9AA6AA4A858DEF04D3049D4E7D22A37F968D050634244EC5DACECCE6160D"),
    "Router.c": ("stock", 2912, "a53dc88ef4d7414dfd2e7c195f0b6215bdf9445f71761f9aa9a43088d209b253",
                 "B952D1A5B03230EE3DA880571FB1438E67B29A0F4101FC76B784F1B7495F3BC1"),
    "IDOMulti.c": ("template", 12657, "22e6cf628f308e2b39c01f87711708deb4a5a348cd6ee66c96674e9e0b741fa6",
                   "330961A6811A03131B590D0C69211447E78DF7208898A44F8CC1E13C629F2D2D"),
}
DOCKER = os.environ.get("HOOK_REPRO_DOCKER_TESTS") == "1"


def sha(b):
    return hashlib.sha256(b).hexdigest()


def hookc_cli(*args):
    return subprocess.run([os.path.join(ROOT, "hookc")] + list(args), capture_output=True, text=True, timeout=3600)


def template_fixture_repo(tmp_path, hh):
    """HandyHooks e5480f9:IssuanceHookset/Fin plus the template headers, committed to a fresh repo
    (the census 'template' mode: headers beside the .c). The source blobs are checked by literal sha256."""
    hdr = os.environ.get("HOOKC_TEMPLATE_HEADERS")
    if not hdr:
        pytest.skip("HOOKC_TEMPLATE_HEADERS not set")
    r = tmp_path / "fin-template"
    r.mkdir()
    names = []
    for n in sorted(git(hh, "ls-tree", "--name-only", HH_COMMIT + ":" + HH_PATH).splitlines()):
        blob = subprocess.run(["git", "-C", hh, "cat-file", "blob", "%s:%s/%s" % (HH_COMMIT, HH_PATH, n)],
                              check=True, capture_output=True).stdout
        (r / n).write_bytes(blob)
        names.append(n)
    for n, h in TEMPLATE_SHA256.items():
        data = open(os.path.join(hdr, n), "rb").read()
        assert sha(data) == h, n
        (r / n).write_bytes(data)
        names.append(n)
    git(tmp_path, "init", "-q", str(r))
    git(r, "add", *names)
    git(r, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "fin + template headers")
    return str(r)


@pytest.mark.skipif(not DOCKER, reason="docker rebuild is opt-in")
@pytest.mark.parametrize("name", sorted(CENSUS))
def test_docker_handyhooks_select_matches_census(name, tmp_path):
    hh = os.environ.get("HANDYHOOKS_REPO")
    if not hh:
        pytest.skip("HANDYHOOKS_REPO not set")
    for n, h in HH_SRC_SHA256.items():
        blob = subprocess.run(["git", "-C", hh, "cat-file", "blob", "%s:%s/%s" % (HH_COMMIT, HH_PATH, n)],
                              check=True, capture_output=True).stdout
        assert sha(blob) == h, n
    headers, size, sha256, hookhash = CENSUS[name]
    if headers == "stock":
        repo, path = hh, HH_PATH
        args = ["--git", hh, "--rev", HH_COMMIT, "--path", HH_PATH]
    else:
        repo, path = template_fixture_repo(tmp_path, hh), ""
        args = ["--git", repo]
    out = tmp_path / "o"
    r = hookc_cli("build", *args, "--toolchain", "buildbox-2026-10", "--select", name, "--out", str(out))
    assert r.returncode == 0, r.stderr[-3000:]
    w = (out / "0.hook.wasm").read_bytes()
    assert (len(w), sha(w), hashlib.sha512(w).digest()[:32].hex().upper()) == (size, sha256, hookhash)
    meta = json.loads((out / "0.hook.metadata.json").read_text())
    assert meta["HookHash"] == hookhash and meta["source"]["entry"] == name
    assert meta["source"]["entry_selector"]["withheld"] == sorted(n for n in HH_SRC_SHA256 if n != name)
    assert meta["builder"]["platforms"]["linux/amd64"]["recipe_digest"] == \
        "8da93100b630d594e1b282f230cf8ae322d9a1082f2b1f2196287d96105c9d4b"
    assert any(c.endswith("-- " + name) for c in meta["builder"]["commands"])  # clang got only the entry
    r2 = hookc_cli("reproduce", "--metadata", str(out / "0.hook.metadata.json"), "--git", repo)
    assert r2.returncode == 0 and "VERDICT: REPRODUCED" in r2.stdout, r2.stdout + r2.stderr[-2000:]


@pytest.mark.skipif(not DOCKER, reason="docker rebuild is opt-in")
def test_docker_handyhooks_directory_build_without_select_still_fails(tmp_path):
    hh = os.environ.get("HANDYHOOKS_REPO")
    if not hh:
        pytest.skip("HANDYHOOKS_REPO not set")
    r = hookc_cli("build", "--git", hh, "--rev", HH_COMMIT, "--path", HH_PATH, "--toolchain", "buildbox-2026-10",
                  "--no-wce", "--out", str(tmp_path / "o"))
    assert r.returncode == 3 and not (tmp_path / "o" / "0.hook.metadata.json").exists()


@pytest.mark.skipif(not DOCKER, reason="docker rebuild is opt-in")
def test_docker_no_select_claimreward_sidecar_byte_identical(tmp_path):
    cr = os.environ.get("CLAIMREWARD_REPO")
    if not cr:
        pytest.skip("CLAIMREWARD_REPO not set")
    out = tmp_path / "o"
    r = hookc_cli("build", "--git", cr, "--rev", "0a10b61b4f361384395a00ebc56e585f8389627f", "--toolchain", "xhc-bin127",
                  "--preset", "classic", "--on", "Cron", "--can-emit", "ClaimReward", "--out", str(out))
    assert r.returncode == 0, r.stderr[-3000:]
    rec = os.path.join(ROOT, "casestudy", "hookc", "claimreward")
    assert (out / "0.hook.metadata.json").read_bytes() == rd(rec, "0.hook.metadata.json")
    assert (out / "0.hook.wasm").read_bytes() == rd(rec, "0.hook.wasm")

"""Regression tests for the 2026-09-29 hostile red-team of hookc / hook-repro (round 3).

Each test is the offline form of one RT round-3 repro script (scratchpad/rt3/r3_*.sh|py).
Where the finding is about WHAT THE CONTAINER CAN SEE (R3-04, R3-05), docker is replaced at the
`docker run` command line by SIM (below): the container's file system is exactly the command's
own `-v` mounts, and the fake compiler reads every path the source probes from cwd /work/src
inside that file system, so a mount of a host dir becomes visible to the bytes exactly as it did
with real docker. Elsewhere the round-1 FAKE CONTAINER is used. Expectations are literals (exit
codes 0/2/3, verdict strings). Every test named test_rt3_* fails on 506ba4e.

  R3-04  the container can read the host --out dir (reused / pre-populated / inside the checkout)
  R3-05  a relative include climbs into the per-arch jail root; single-twin verify hides it
"""
import hashlib
import json
import os
import posixpath
import re
import shutil

import pytest

from hook_repro import build as B, cli, fetch as F, hookc as HC, verify as V
from hook_repro.hashing import sha512half

from test_rt_round1 import FAKE_LOG, HOOK_C, fake, git, hookc, load, mkrepo, rd, save  # noqa: F401

ARM = ["--platform", "linux/arm64"]
TC_ARM = ["--toolchain", "hookc-llvm22", "--platform", "linux/arm64"]
PROBE_RE = re.compile(rb"^#define PROBE\w* (\S+)", re.M)


# ---------------- SIM: docker run, file system = the command's own mounts ----------------

def _mounts(cmd):
    """{container path: host path} from -v flags; a chroot /jail strips the /jail prefix."""
    jail = "chroot" in cmd
    out = {}
    for k, a in enumerate(cmd):
        if a == "-v":
            host, ctr = cmd[k + 1].split(":")[:2]
            if jail:
                assert ctr.startswith("/jail/")
                ctr = ctr[len("/jail"):]
            out[ctr] = host
    return out


def _resolve(mounts, platform, path):
    """What the file at `path` (relative to cwd /work/src, which is a copy of /src) is inside the
    container: bytes, or None if absent. /usr/lib/<arch>-linux-gnu is the per-arch base image."""
    full = posixpath.normpath(posixpath.join("/work/src", path))
    if full.startswith("/work/src/") or full == "/work/src":
        full = "/src" + full[len("/work/src"):]
    arch_lib = "/usr/lib/%s-linux-gnu" % {"linux/arm64": "aarch64", "linux/amd64": "x86_64"}[platform]
    if full.startswith(arch_lib):
        return b"libc of " + platform.encode()
    for ctr, host in mounts.items():
        if full == ctr or full.startswith(ctr + "/"):
            hp = os.path.join(host, full[len(ctr):].lstrip("/"))
            if os.path.isfile(hp):
                with open(hp, "rb") as f:
                    return f.read()
            return None
    return None


def sim_compile(cmd):
    """The fake pipeline: compiles the /src mount + every PROBE path, writes /out/hook.wasm."""
    mounts = _mounts(cmd)
    platform = cmd[cmd.index("--platform") + 1]
    src = mounts["/src"]
    view = []
    for dp, dn, fn in os.walk(src):
        for f in sorted(fn):
            full = os.path.join(dp, f)
            with open(full, "rb") as fh:
                data = fh.read()
            view.append((os.path.relpath(full, src), hashlib.sha256(data).hexdigest()))
            for p in PROBE_RE.findall(data):
                got = _resolve(mounts, platform, p.decode())
                view.append(("probe:" + p.decode(), None if got is None else hashlib.sha256(got).hexdigest()))
    digest = hashlib.sha256(json.dumps(sorted(view)).encode()).digest()
    payload = bytes([3]) + b"src" + digest
    wasm = rd("tiny.wasm") + bytes([0, len(payload)]) + payload
    out = mounts["/out"]
    with open(os.path.join(out, "hook.wasm"), "wb") as f:
        f.write(wasm)
    with open(os.path.join(out, "build.txt"), "w") as f:
        f.write(FAKE_LOG)
    return wasm


class _Done:
    returncode, stdout, stderr = 0, "", ""


@pytest.fixture
def sim(monkeypatch, tmp_path):
    runs = []

    def run_named(cmd, name, timeout):
        assert cmd[:2] == ["docker", "run"]
        runs.append({"cmd": list(cmd), "out_before": sorted(os.listdir(_mounts(cmd)["/out"]))})
        sim_compile(cmd)
        return _Done()
    monkeypatch.setattr(B, "CACHE", str(tmp_path / "cache"))
    monkeypatch.setattr(B, "run_named", run_named)
    monkeypatch.setattr(B, "ensure_image", lambda recipe, log=print: {
        "tag": "t", "image_id": "sha256:sim-" + recipe["platform"], "recipe_digest": B.recipe_digest(recipe)})
    monkeypatch.setattr(B, "docker_available", lambda: True)
    monkeypatch.setattr(HC, "run_wce", lambda w, log=None: ({"hook": 20, "cbak": 0}, None))
    return runs


def sidecar_hash(out):
    return load(os.path.join(str(out), "0.hook.metadata.json"))["HookHash"]


def repro(m, repo, *extra):
    return hookc("reproduce", "--metadata", m, "--git", repo, *extra)


# ---------------- R3-04: the container never sees a host-writable or pre-existing dir ----------------

PROBE_OUT_WASM = (b'#include "hookapi.h"\n#define PROBE_OUT ../../out/hook.wasm   /* macro-computed: the pre-scan '
                  b'cannot see it */\nint64_t hook(uint32_t r) { _g(1,1); return accept(0, 0, 0); }\n')
PROBE_PAYLOAD = (b'#include "hookapi.h"\n#define PROBE_PAYLOAD ../../out/payload.h\n'
                 b'int64_t hook(uint32_t r) { _g(1,1); return accept(0, 0, 0); }\n')


def test_rt3_04a_rebuild_into_the_same_out_never_flips(sim, tmp_path):
    # r3_04a_out_dir_rerun.sh: a 2nd build into the same --out saw run 1's hook.wasm in /out
    r = mkrepo(tmp_path / "repo", {"hook.c": PROBE_OUT_WASM})
    assert hookc("build", "--git", r, *TC_ARM, "--out", tmp_path / "o") == 0
    h1 = sidecar_hash(tmp_path / "o")
    assert hookc("build", "--git", r, *TC_ARM, "--out", tmp_path / "o") == 0
    h2 = sidecar_hash(tmp_path / "o")
    assert hookc("build", "--git", r, *TC_ARM, "--out", tmp_path / "fresh") == 0
    assert h1 == h2 == sidecar_hash(tmp_path / "fresh")  # same bytes as a build into a fresh dir
    m = str(tmp_path / "o" / "0.hook.metadata.json")
    assert repro(m, r) == 0                                  # control: fresh tmp out
    assert repro(m, r, "--out", tmp_path / "rev") == 0       # reviewer run 1
    assert repro(m, r, "--out", tmp_path / "rev") == 0       # reviewer run 2 into the same --out: no flip


def test_rt3_04_planted_out_files_do_not_reach_the_bytes(sim, tmp_path):
    # r3_04_out_dir_include.sh: the attacker pre-populated the build's out dir with payload.h
    r = mkrepo(tmp_path / "repo", {"hook/hook.c": PROBE_PAYLOAD})
    assert hookc("build", "--git", r, "--path", "hook", *TC_ARM, "--out", tmp_path / "clean") == 0
    for b in ("build1", "build2"):
        d = tmp_path / "o" / "builds" / "linux-arm64" / b
        d.mkdir(parents=True)
        (d / "payload.h").write_bytes(b"#define PAYLOAD 0x31337\n")
    assert hookc("build", "--git", r, "--path", "hook", *TC_ARM, "--out", tmp_path / "o") == 0
    assert sidecar_hash(tmp_path / "o") == sidecar_hash(tmp_path / "clean")
    m = str(tmp_path / "o" / "0.hook.metadata.json")
    rev = tmp_path / "rev" / "linux-arm64"
    for b in ("build1", "build2"):
        (rev / b).mkdir(parents=True)
        (rev / b / "payload.h").write_bytes(b"#define PAYLOAD 0x31337\n")
    assert repro(m, r, "--out", tmp_path / "rev") == 0 and repro(m, r) == 0


def test_rt3_04_out_inside_the_reviewed_checkout_refused(sim, tmp_path):
    # r3_04 (b) / r3_04b: `--src . --out repro` inside the checkout (payload committed there)
    r = mkrepo(tmp_path / "repo", {"hook/hook.c": PROBE_PAYLOAD,
                                   "repro/linux-arm64/build1/payload.h": b"#define PAYLOAD 0x31337\n",
                                   "repro/linux-arm64/build2/payload.h": b"#define PAYLOAD 0x31337\n"})
    assert hookc("build", "--git", r, "--path", "hook", *TC_ARM, "--out", tmp_path / "o") == 0
    m = str(tmp_path / "o" / "0.hook.metadata.json")
    n = len(sim)
    assert hookc("reproduce", "--metadata", m, "--src", r, "--out", r / "repro") == 3
    assert hookc("reproduce", "--metadata", m, "--git", r, "--out", r / "repro") == 3
    assert hookc("reproduce", "--metadata", m, "--src", r, "--out", r) == 3
    assert hookc("build", "--git", r, "--path", "hook", *TC_ARM, "--out", r / "o") == 3
    assert len(sim) == n  # refused before any container ran
    assert hookc("reproduce", "--metadata", m, "--src", r, "--out", tmp_path / "outside") == 0


def stub_chain(monkeypatch, wasm, fee="20"):
    h = sha512half(wasm)

    def t(url, payload, timeout=20):
        if payload["method"] == "server_info":
            return {"result": {"status": "success", "info": {"pubkey_node": "n9STUB" + url[-8:], "network_id": 21337,
                                                              "build_version": "stub"}}}
        node = {"LedgerEntryType": "HookDefinition", "HookHash": h, "CreateCode": wasm.hex().upper(), "Fee": fee}
        return {"result": {"status": "success", "validated": True, "ledger_index": 100, "ledger_hash": "AB" * 32,
                           "node": node}}
    monkeypatch.setattr(F, "http_transport", t)
    return h


def verify(h, m, *extra):
    return cli.main(["verify", "--hookhash", h, "--metadata", m] + [str(a) for a in extra])


def test_rt3_04b_verify_out_dir_is_never_read_by_the_rebuild(sim, tmp_path, monkeypatch):
    # r3_04b_verify_out_dir.sh: verify built into DIR/build1, DIR/build2, readable as ../../out/
    r = mkrepo(tmp_path / "repo", {"hook/hook.c": PROBE_PAYLOAD,
                                   "vout/build1/payload.h": b"#define PAYLOAD 0x31337\n",
                                   "vout/build2/payload.h": b"#define PAYLOAD 0x31337\n"})
    assert hookc("build", "--git", r, "--path", "hook", *TC_ARM, "--out", tmp_path / "o") == 0
    m = str(tmp_path / "o" / "0.hook.metadata.json")
    h = stub_chain(monkeypatch, (tmp_path / "o" / "0.hook.wasm").read_bytes())
    assert verify(h, m, "--src", r, "--out", r / "vout", *ARM) == 3            # inside the checkout: refused
    out = tmp_path / "vout"
    for b in ("build1", "build2", "linux-arm64/build1", "linux-arm64/build2"):
        (out / b).mkdir(parents=True)
        (out / b / "payload.h").write_bytes(b"#define PAYLOAD 0x31337\n")
    assert verify(h, m, "--git", r, "--out", out) == 0
    rep = load(out / "verify-report.json")
    fresh = tmp_path / "fresh"
    assert verify(h, m, "--git", r, "--out", fresh) == 0
    assert [b["sha512half"] for b in rep["builds"]] == [b["sha512half"] for b in load(fresh / "verify-report.json")["builds"]]


def test_rt3_04_container_out_mount_is_fresh_private_and_empty(sim, tmp_path):
    (tmp_path / "user-out").mkdir()
    (tmp_path / "user-out" / "left-over").write_bytes(b"stale")
    src = tmp_path / "src"
    src.mkdir()
    (src / "hook.c").write_bytes(HOOK_C)
    m, w = B.build(str(src), "hookc-llvm22", out_dir=str(tmp_path / "user-out"), log=lambda *_: None)
    cmd = sim[-1]["cmd"]
    mounts = _mounts(cmd)
    assert sorted(mounts) == ["/out", "/src"]                             # nothing else mounted
    assert "%s:/jail/src:ro" % mounts["/src"] in cmd                      # source read-only
    assert os.path.realpath(mounts["/out"]) != os.path.realpath(tmp_path / "user-out")
    assert os.path.realpath(mounts["/out"]).startswith(os.path.realpath(B.CACHE))
    assert sim[-1]["out_before"] == []                                    # empty when the container started
    assert not os.path.exists(mounts["/out"])                             # private dir removed afterwards
    assert (tmp_path / "user-out" / "hook.wasm").read_bytes() == w        # outputs published after the build
    assert (tmp_path / "user-out" / "left-over").read_bytes() == b"stale"
    assert os.stat(tmp_path / "user-out" / "hook.wasm").st_mode & 0o777 == 0o644


def test_rt3_04_run_container_refuses_a_non_empty_out(tmp_path, monkeypatch):
    def no_docker(*a, **k):
        raise AssertionError("docker must not run with a non-empty out dir")
    monkeypatch.setattr(B, "run_named", no_docker)
    (tmp_path / "x").write_bytes(b"x")
    with pytest.raises(B.BuildError, match="not empty"):
        B.run_container(B.load_recipe("hookc-llvm22"), {"image_id": "sha256:x"}, str(tmp_path), str(tmp_path), {})


def test_rt3_04_hook_repro_build_out_inside_src_refused(sim, tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "hook.c").write_bytes(HOOK_C)
    assert cli.main(["build", str(src), "--recipe", "hookc-llvm22", "--out", str(src / "o")]) == 3
    with pytest.raises(B.BuildError, match="inside the source"):
        B.build(str(src), "hookc-llvm22", out_dir=str(src), log=lambda *_: None)
    assert cli.main(["build", str(src), "--recipe", "hookc-llvm22", "--out", str(tmp_path / "o")]) == 0


def test_guard_04_publish_replaces_planted_symlink_without_following_it(sim, tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    victim = tmp_path / "victim"
    victim.write_bytes(b"keep")
    os.symlink(victim, out / "hook.wasm")
    src = tmp_path / "src"
    src.mkdir()
    (src / "hook.c").write_bytes(HOOK_C)
    B.build(str(src), "hookc-llvm22", out_dir=str(out), log=lambda *_: None)
    assert victim.read_bytes() == b"keep" and not os.path.islink(out / "hook.wasm")


def test_guard_04_non_regular_pipeline_output_refused(tmp_path):
    (tmp_path / "p").mkdir()
    (tmp_path / "p" / "d").mkdir()
    with pytest.raises(B.BuildError, match="non-regular"):
        B.publish_outputs(str(tmp_path / "p"), str(tmp_path / "o"))


def test_guard_04_out_inside_matches_only_real_containment(tmp_path):
    assert B.out_inside(str(tmp_path / "a" / "b"), str(tmp_path / "a")) == str(tmp_path / "a")
    assert B.out_inside(str(tmp_path / "a"), str(tmp_path / "a")) == str(tmp_path / "a")
    assert B.out_inside(str(tmp_path / "ab"), str(tmp_path / "a")) is None     # sibling with a common prefix
    assert B.out_inside(str(tmp_path), str(tmp_path / "a")) is None            # out contains the source: fine
    assert B.out_inside(str(tmp_path / "a"), None, "") is None


# ---------------- '..' belt of the lexical pre-scan (R3-04 / R3-05) ----------------

@pytest.mark.parametrize("src", [
    b'#if __has_include("../../out/hook.wasm")\n#endif\n',                              # r3_04a
    b'#if __has_include("../../out/payload.h")\n#include "../../out/payload.h"\n#endif\n',  # r3_04 / r3_04b
    b'#if __has_include("../../usr/lib/aarch64-linux-gnu/libc.so.6")\n#endif\n',        # r3_05
    b'#include "sub/../../x.h"\n', b'#include <../x.h>\n', b'  #  include_next "../x"\n',
    b'#embed "../../out/x" limit(1)\n', b'#if __has_embed("..\\\\x")\n#endif\n',
    b'__asm__(".incbin \\"../../out/x\\"");\n', b'#include ".\\\n./x.h"\n', b'#include " ../x.h"\n',
    b'#include "ok.h"\n#include "../x.h"\n'])
def test_rt3_05_parent_relative_include_like_operands_refused(sim, tmp_path, src):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C, "inc/x.h": src})
    n = len(sim)
    assert hookc("build", "--git", r, *TC_ARM, "--out", tmp_path / "o") == 3
    assert len(sim) == n


@pytest.mark.parametrize("src", [b'#include "a..b.h"\n', b'#include "x/..h"\n', b'const char *p = "../x";\n',
                                 b'// #include "../x"\n', b'#include "x.h"\n'])
def test_guard_05_dotted_names_that_are_not_parent_components_accepted(sim, tmp_path, src):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C, "inc/x.h": src})
    assert hookc("build", "--git", r, *TC_ARM, "--out", tmp_path / "o") == 0


# ---------------- R3-01: exports are (name, kind, index); a name may contain ':' ----------------

def _vec(items):
    return bytes([len(items)]) + b"".join(items)


def _name(s):
    return bytes([len(s)]) + s


def crafted_module(func_exports, other=()):
    """A literal wasm module: n functions (i32)->i64 returning 0, exported under the given
    names (in order, indices 0..n-1), plus one i32 global exported under each name in other."""
    n = len(func_exports)
    sec = lambda sid, body: bytes([sid, len(body)]) + body  # noqa: E731
    out = b"\0asm\1\0\0\0" + sec(1, _vec([b"\x60\x01\x7f\x01\x7e"])) + sec(3, _vec([b"\x00"] * n))
    if other:
        out += sec(6, _vec([b"\x7f\x00\x41\x00\x0b"]))
    exps = [_name(nm) + b"\x00" + bytes([i]) for i, nm in enumerate(func_exports)]
    exps += [_name(nm) + b"\x03\x00" for nm in other]
    out += sec(7, _vec(exps))
    return out + sec(10, _vec([b"\x04\x00\x42\x00\x0b"] * n))


def test_guard_01_crafted_module_parses_as_intended():
    from hook_repro.wasm import parse
    assert parse(crafted_module([b"hook", b"cbak:0"], [b"cbak"]))["export_entries"] == [
        ("hook", 0, 0), ("cbak:0", 0, 1), ("cbak", 3, 0)]


@pytest.mark.parametrize("names", [[b"hook", b"cbak:0", b"evil:fn"], [b"hook", b"cbak:0"], [b"hook", b"evil:fn"],
                                   [b"hook", b"cbak", b"hook:0"], [b"hook", b"cbak "]])
def test_rt3_01_colon_named_function_exports_refused(fake, tmp_path, names):
    # r3_01_colon_export.sh: "cbak:0" was taken for cbak, "evil:fn" escaped the extra-export refusal
    fake["wasm"] = crafted_module(names)
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    assert hookc("build", "--git", r, *TC_ARM, "--out", tmp_path / "o") == 3
    with pytest.raises(HC.HookcError, match="other than exactly"):
        HC.make_metadata(HC.normalize_decls({})[0], fake["wasm"], None, HC.NO_WCE_REASON, "hookc-llvm22", "deploy",
                         {"ENTRY": ""}, "", {}, ["linux/arm64"])


def test_guard_01_cbak_fn_only_for_a_real_cbak_function_export(fake, tmp_path):
    fake["wasm"] = crafted_module([b"hook"], [b"cbak"])  # a GLOBAL named cbak is not a callback
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    assert hookc("build", "--git", r, *TC_ARM, "--out", tmp_path / "o") == 0
    assert load(tmp_path / "o" / "0.hook.metadata.json")["cbak_fn"] is None
    fake["wasm"] = crafted_module([b"hook", b"cbak"])
    assert hookc("build", "--git", r, *TC_ARM, "--out", tmp_path / "o2") == 0
    assert load(tmp_path / "o2" / "0.hook.metadata.json")["cbak_fn"] == "cbak"


def test_guard_01_duplicate_function_export_name_refused():
    with pytest.raises(HC.HookcError, match="twice"):
        HC.exports_of(crafted_module([b"hook", b"hook"]))


# ---------------- R3-02: builder.wasm_opt comes from the stage that ran, not from command lines ----------------

C_PIPELINES = ["hookc-llvm22", "hookc-llvm22-amd64", "kvt-llvm22", "kvt-llvm22-amd64", "xhc-bin127"]
FAKE_TOOLS = {
    "clang": '[ "${1:-}" = --version ] && { echo "clang version fake"; exit 0; }\n'
             'o=; n=; for a in "$@"; do [ "$n" = 1 ] && o=$a; n=; [ "$a" = -o ] && n=1; done\n'
             'printf "WASM %s\\n" "$*" > "$o"\n',
    "wasm-opt": '[ "${1:-}" = --version ] && { echo "wasm-opt version fake"; exit 0; }\n'
                '[ -n "${FAKE_WASM_OPT_FAIL:-}" ] && exit 1\n'
                'o=; n=; i=; for a in "$@"; do [ "$n" = 1 ] && o=$a && n= && continue; [ "$a" = -o ] && n=1 && continue;'
                ' [ -f "$a" ] && i=$a; done\n'
                'cat "$i" > "$o.tmp"; echo opt >> "$o.tmp"; mv "$o.tmp" "$o"; echo ran >> "$FAKE_LOG_DIR/wasm-opt.calls"\n',
    "wasm-strip": '[ "${1:-}" = --version ] && { echo 1.0.41; exit 0; }\nexit 0\n',
    "wasm-validate": "exit 0\n",
    "hook-cleaner": "exit 0\n",
    "guard_checker": "exit 0\n",
    "sha512sum": 'shasum -a 512 "$1"\n',
}


def run_pipeline(recipe, tmp_path, files, **env):
    """The recipe's REAL pipeline.sh, with /tc /work /out /src /hdr re-rooted under tmp_path and
    every tool a fake that records whether it ran. Returns (exit, build.txt or None, wasm-opt runs)."""
    root = tmp_path / "root"
    for d in ("src", "out", "work", "tc", "bin"):
        (root / d).mkdir(parents=True)
    for name, data in files.items():
        (root / "src" / name).write_bytes(data)
    tools = {"bin": ["sha512sum"], "tc/llvm/bin": ["clang"], "tc/binaryen/bin": ["wasm-opt"],
             "tc/wabt/bin": ["wasm-strip", "wasm-validate"], "tc/wasi-sdk/bin": ["clang"], "tc": ["wasm-opt", "hook-cleaner",
                                                                                                "guard_checker"]}
    for d, names in tools.items():
        (root / d).mkdir(parents=True, exist_ok=True)
        for n in names:
            (root / d / n).write_text("#!/bin/sh\n" + FAKE_TOOLS[n])
            (root / d / n).chmod(0o755)
    (root / "tc" / "guard_hoist.py").write_text("import sys\n")
    s = open(os.path.join(B.RECIPES_DIR, recipe, "pipeline.sh")).read()
    s = re.sub(r'(?<=[\s"=:>])/(tc|work|out|src|hdr)\b', lambda m: str(root) + "/" + m.group(1), s)
    import subprocess
    e = {"PATH": str(root / "bin") + ":" + os.environ["PATH"], "LC_ALL": "C", "ENTRY": "", "FAKE_LOG_DIR": str(root)}
    e.update(env)
    r = subprocess.run(["/bin/sh", "-c", s], capture_output=True, env=e)
    bt = root / "out" / "build.txt"
    calls = root / "wasm-opt.calls"
    return (r.returncode, bt.read_text() if bt.exists() else None,
            len(calls.read_text().splitlines()) if calls.exists() else 0)


def test_rt3_02_xhc_clean_only_build_of_wasm_opt_c_says_wasm_opt_did_not_run(tmp_path):
    # r3_02_wasm_opt_field.sh: a top-level wasm-opt.c put "wasm-opt" into clang's command line
    rc, log, runs = run_pipeline("xhc-bin127", tmp_path, {"wasm-opt.c": b"int x;\n"},
                                 CLANG_OPT="-O2", WASMOPT="-O2", STAGES="clean")
    assert rc == 0 and runs == 0
    assert any("wasm-opt.c" in c for c in HC._log_commands(log))  # the substring trap is present
    d = HC.make_metadata(HC.normalize_decls({})[0], rd("tiny.wasm"), None, HC.NO_WCE_REASON, "xhc-bin127", None,
                         {"CLANG_OPT": "-O2", "STAGES": "clean", "WASMOPT": "-O2"}, log, {}, ["linux/amd64"])
    assert d["builder"]["wasm_opt"] is False


@pytest.mark.parametrize("stages,wasmopt,ran", [("opt,clean", "-O2", True), ("clean,opt", "builder2025", True),
                                                ("opt,clean", "none", False), ("clean", "-O2", False),
                                                ("opt,clean,opt", "-O2", True)])
def test_rt3_02_xhc_flag_follows_the_stage_that_executed(tmp_path, stages, wasmopt, ran):
    rc, log, runs = run_pipeline("xhc-bin127", tmp_path, {"hook.c": b"int x;\n"},
                                 CLANG_OPT="-O2", WASMOPT=wasmopt, STAGES=stages)
    assert rc == 0 and (runs > 0) is ran and HC.wasm_opt_ran(log) is ran


@pytest.mark.parametrize("recipe", C_PIPELINES[:4])
def test_rt3_02_llvm_pipelines_state_wasm_opt_ran(recipe, tmp_path):
    rc, log, runs = run_pipeline(recipe, tmp_path, {"wasm-opt.c": b"int x;\n"})
    assert rc == 0 and runs == 1 and HC.wasm_opt_ran(log) is True
    assert [ln for ln in log.splitlines() if ln.startswith("HOOKC_WASM_OPT_RAN")] == ["HOOKC_WASM_OPT_RAN=1"]


@pytest.mark.parametrize("recipe", C_PIPELINES)
def test_guard_02_failed_wasm_opt_leaves_no_build(recipe, tmp_path):
    rc, log, _ = run_pipeline(recipe, tmp_path, {"hook.c": b"int x;\n"}, CLANG_OPT="-O2", WASMOPT="-O2",
                              STAGES="opt,clean", FAKE_WASM_OPT_FAIL="1")
    assert rc != 0 and log is None


@pytest.mark.parametrize("log", ["", "--- commands\nHOOKC_WASM_OPT_RAN=1\n", "HOOKC_WASM_OPT_RAN=1\nHOOKC_WASM_OPT_RAN=1\n",
                                 "HOOKC_WASM_OPT_RAN=2\n", "HOOKC_WASM_OPT_RAN=1 \n", "HOOKC_WASM_OPT_RAN=yes\n",
                                 "HOOKC_WASM_OPT_RAN=0\nHOOKC_WASM_OPT_RAN=1\n"])
def test_rt3_02_missing_repeated_or_malformed_flag_refused(log):
    with pytest.raises(HC.HookcError, match="HOOKC_WASM_OPT_RAN"):
        HC.make_metadata(HC.normalize_decls({})[0], rd("tiny.wasm"), None, HC.NO_WCE_REASON, "xhc-bin127", None,
                         {"CLANG_OPT": "-O2", "STAGES": "clean", "WASMOPT": "-O2"}, "sources: x.c\n" + log, {},
                         ["linux/amd64"])


def test_guard_02_flag_values():
    assert HC.wasm_opt_ran("a: b\nHOOKC_WASM_OPT_RAN=0\n--- commands\nwasm-opt -O2\n") is False
    assert HC.wasm_opt_ran("HOOKC_WASM_OPT_RAN=1\n--- stages\nHOOKC_WASM_OPT_RAN=0\n") is True


# ---------------- R3-03 / R3-05: verify re-checks every twin in builder.platforms_built ----------------

def verify_runs(sim, n):
    return sorted(c["cmd"][c["cmd"].index("--platform") + 1] for c in sim[n:])


def test_rt3_03_verify_restricted_to_one_twin_says_platforms_built_not_rechecked(sim, tmp_path, monkeypatch):
    # r3_03_verify_platforms_built.sh: arm64-only build, platforms_built forged to both twins,
    # `verify --platform linux/arm64` said REPRODUCED with no word about platforms_built
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    assert hookc("build", "--git", r, *TC_ARM, "--out", tmp_path / "o") == 0
    d = load(tmp_path / "o" / "0.hook.metadata.json")
    d["builder"]["platforms_built"] = ["linux/amd64", "linux/arm64"]
    forged = save(tmp_path / "forged.json", d)
    h = stub_chain(monkeypatch, (tmp_path / "o" / "0.hook.wasm").read_bytes())
    assert verify(h, forged, "--git", r, *ARM, "--out", tmp_path / "v") == 0
    rep = load(tmp_path / "v" / "verify-report.json")
    assert rep["platforms_built_rechecked"] is False and rep["platforms_rebuilt"] == ["linux/arm64"]
    assert "platforms_built linux/amd64+linux/arm64 is the original build's record, NOT re-checked" in rep["reason"]


def test_rt3_03_verify_rebuilds_every_twin_in_platforms_built_by_default(sim, tmp_path, monkeypatch):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    assert hookc("build", "--git", r, "--toolchain", "hookc-llvm22", "--out", tmp_path / "o") == 0
    m = str(tmp_path / "o" / "0.hook.metadata.json")
    h = stub_chain(monkeypatch, (tmp_path / "o" / "0.hook.wasm").read_bytes())
    n = len(sim)
    assert verify(h, m, "--git", r, "--out", tmp_path / "v") == 0
    assert verify_runs(sim, n) == ["linux/amd64"] * 2 + ["linux/arm64"] * 2  # both twins, twice each
    rep = load(tmp_path / "v" / "verify-report.json")
    assert rep["platforms_built_rechecked"] is True and rep["platforms_rebuilt"] == ["linux/amd64", "linux/arm64"]
    assert "platforms_built linux/amd64+linux/arm64 re-checked" in rep["reason"]
    assert [(b["platform"], b["n"]) for b in rep["builds"]] == [("linux/amd64", 1), ("linux/amd64", 2),
                                                                ("linux/arm64", 1), ("linux/arm64", 2)]
    assert (tmp_path / "v" / "linux-amd64" / "build2" / "hook.wasm").exists()


PROBE_ARCH = (b'#include "hookapi.h"\n#define PROBE_ARCH ../../usr/lib/aarch64-linux-gnu/libc.so.6  /* macro-computed:'
              b' not seen by the pre-scan */\nint64_t hook(uint32_t r) { _g(1,1); return accept(0, 0, 0); }\n')


@pytest.mark.parametrize("built,other", [("linux/arm64", "linux/amd64"), ("linux/amd64", "linux/arm64")])
def test_rt3_05_single_twin_build_whose_other_twin_diverges_is_reported(sim, tmp_path, monkeypatch, built, other):
    # r3_05_twin_divergence.sh: the twins build different bytes (per-arch jail root); an arm64-only
    # build + forged platforms_built passed `verify` (one twin, no re-check, no caveat)
    r = mkrepo(tmp_path / "repo", {"hook.c": PROBE_ARCH})
    assert hookc("build", "--git", r, "--toolchain", "hookc-llvm22", "--out", tmp_path / "all") == 3
    assert hookc("build", "--git", r, "--toolchain", "hookc-llvm22", "--platform", built, "--out", tmp_path / "o") == 0
    d = load(tmp_path / "o" / "0.hook.metadata.json")
    d["builder"]["platforms_built"] = ["linux/amd64", "linux/arm64"]
    forged = save(tmp_path / "forged.json", d)
    assert repro(forged, r) == 2                                              # reproduce: every claimed twin
    h = stub_chain(monkeypatch, (tmp_path / "o" / "0.hook.wasm").read_bytes())
    assert verify(h, forged, "--git", r, "--out", tmp_path / "v") == 2         # verify: every claimed twin
    rep = load(tmp_path / "v" / "verify-report.json")
    assert rep["verdict"] == "MISMATCH" and "(%s twin)" % other in rep["reason"]
    assert rep["platforms_built_rechecked"] is False
    assert verify(h, forged, "--git", r, "--platform", built, "--out", tmp_path / "v1") == 0  # restricted: said so
    rep = load(tmp_path / "v1" / "verify-report.json")
    assert rep["platforms_built_rechecked"] is False and "NOT re-checked" in rep["reason"]


def test_guard_05_honest_single_twin_sidecar_verifies_rechecked(sim, tmp_path, monkeypatch):
    r = mkrepo(tmp_path / "repo", {"hook.c": PROBE_ARCH})
    assert hookc("build", "--git", r, *TC_ARM, "--out", tmp_path / "o") == 0
    h = stub_chain(monkeypatch, (tmp_path / "o" / "0.hook.wasm").read_bytes())
    n = len(sim)
    assert verify(h, str(tmp_path / "o" / "0.hook.metadata.json"), "--git", r, "--out", tmp_path / "v") == 0
    assert verify_runs(sim, n) == ["linux/arm64"] * 2
    assert load(tmp_path / "v" / "verify-report.json")["platforms_built_rechecked"] is True


def test_guard_03_verify_twin_nondeterminism_and_build_failure_name_the_twin(tmp_path):
    from test_core import transport_from
    from test_rt_round1 import MAIN, recorded
    good = rd("claimreward_onledger.wasm")
    H = sha512half(good)
    seq = iter([good, good, good, good + b"x"])

    def builder(src, rname, params, preset, out):
        return ({"recipe": {"digest": rname}, "image": {"image_id": "i"}, "source": {"tree_sha256": "t"},
                 "params": {}}, next(seq))
    twins = [("linux/amd64", "xhc-bin127"), ("linux/arm64", "other")]
    rep = V.verify(H, str(tmp_path), "xhc-bin127", "mainnet", transport=transport_from(recorded()), builder=builder,
                   endpoints=MAIN, twins=twins)
    assert rep["verdict"] == "UNVERIFIED" and "on linux/arm64 is NOT deterministic" in rep["reason"]

    def broken(src, rname, params, preset, out):
        if rname == "other":
            raise RuntimeError("no arm64")
        return builder(src, rname, params, preset, out)
    seq = iter([good, good])
    meta = {"hookhash": H, "doc": {}, "platforms_built": ["linux/amd64", "linux/arm64"]}
    rep = V.verify(H, str(tmp_path), "xhc-bin127", "mainnet", transport=transport_from(recorded()), builder=broken,
                   endpoints=MAIN, twins=twins, metadata=meta, sidecar=lambda w, m, b: (True, None, []))
    assert rep["verdict"] == "UNVERIFIED" and "rebuild 1 on linux/arm64 failed" in rep["reason"]
    assert rep["platforms_rebuilt"] == ["linux/amd64"] and rep["platforms_built_rechecked"] is False


# ---------------- R3-07: git tree order (fsck treeNotSorted) and reserved vcs.path components ----------------

def _hash(r, kind, body):
    import subprocess
    return subprocess.run(["git", "-C", str(r), "hash-object", "-w", "--literally", "-t", kind, "--stdin"],
                          input=body, capture_output=True, check=True).stdout.decode().strip()


def raw_tree(r, entries):
    return _hash(r, "tree", b"".join(m + b" " + n + b"\0" + bytes.fromhex(o) for m, n, o in entries))


def raw_commit(r, tree):
    return _hash(r, "commit", b"tree " + tree.encode() + b"\nauthor a <a@b> 0 +0000\ncommitter a <a@b> 0 +0000\n\nm\n")


def fsck_tree_errors(r):
    import subprocess
    p = subprocess.run(["git", "-C", str(r), "fsck", "--strict", "--no-dangling"], capture_output=True)
    return p.stderr.decode()


def export(r, c, path, tmp_path):
    return HC.export_tree(str(r), c, path, str(tmp_path / ("x%d" % len(os.listdir(tmp_path)))))


@pytest.fixture
def objrepo(tmp_path):
    r = tmp_path / "objs"
    git(tmp_path, "init", "-q", str(r))
    a = _hash(r, "blob", HOOK_C)
    b = _hash(r, "blob", b"/* b */\n")
    return r, a, b


def test_rt3_07_unsorted_tree_refused(objrepo, tmp_path):
    # r3_07_git_reader_edges.py: tree [b.c, a.c] was ACCEPTED (git fsck: treeNotSorted)
    r, a, b = objrepo
    c = raw_commit(r, raw_tree(r, [(b"100644", b"b.c", b), (b"100644", b"a.c", a)]))
    assert "treeNotSorted" in fsck_tree_errors(r)
    with pytest.raises(HC.HookcError, match="not sorted"):
        export(r, c, "", tmp_path)
    assert hookc("build", "--git", r, "--rev", c, *TC_ARM, "--out", tmp_path / "o") == 3


def test_rt3_07_tree_sorts_as_name_slash(objrepo, tmp_path):
    # a tree `a` sorts as "a/", i.e. AFTER a blob "a.c" ('.' 0x2e < '/' 0x2f); plain byte order says before
    r, a, b = objrepo
    sub = raw_tree(r, [(b"100644", b"x.h", b)])
    bad = raw_commit(r, raw_tree(r, [(b"40000", b"a", sub), (b"100644", b"a.c", a)]))
    assert "treeNotSorted" in fsck_tree_errors(r)
    with pytest.raises(HC.HookcError, match="not sorted"):
        export(r, bad, "", tmp_path)


def test_guard_07_git_ordered_trees_accepted_as_fsck_does(objrepo, tmp_path):
    r, a, b = objrepo
    sub = raw_tree(r, [(b"100644", b"x.h", b)])
    good = raw_commit(r, raw_tree(r, [(b"100644", b"a", b), (b"100644", b"a.c", a), (b"100644", b"a0.c", b),
                                      (b"40000", b"a0", sub), (b"40000", b"b", sub)]))
    assert "error" not in fsck_tree_errors(r)
    names = [n for n, _ in export(r, good, "", tmp_path)["listing"]]
    assert names == ["a", "a.c", "a0.c", "a0/x.h", "b/x.h"]
    wrong = raw_commit(r, raw_tree(r, [(b"100644", b"a0.c", b), (b"40000", b"a0", sub), (b"100644", b"a.c", a)]))
    with pytest.raises(HC.HookcError, match="not sorted"):  # and hookc refuses what fsck refuses
        export(r, wrong, "", tmp_path)
    assert "treeNotSorted" in fsck_tree_errors(r)
    assert HC.tree_sort_key("40000", b"a") == b"a/" and HC.tree_sort_key("100644", b"a") == b"a"


@pytest.mark.parametrize("comp", [".git", ".GIT", ".Git", "__pycache__", ".hook-repro"])
@pytest.mark.parametrize("where", ["{}", "sub/{}", "{}/deeper"])
def test_rt3_07_reserved_component_anywhere_in_vcs_path_refused(objrepo, tmp_path, comp, where):
    # r3_07: vcs.path '.git' / '.GIT' (a tree entry named .git) was ACCEPTED
    r, a, b = objrepo
    path = where.format(comp)
    t = raw_tree(r, [(b"100644", b"a.c", a)])
    for part in reversed(path.split("/")):
        t = raw_tree(r, [(b"40000", part.encode(), t)])
    c = raw_commit(r, t)
    with pytest.raises(HC.HookcError, match="reserved component"):
        export(r, c, path, tmp_path)
    assert hookc("build", "--git", r, "--rev", c, "--path", path, *TC_ARM, "--out", tmp_path / "o") == 3


@pytest.mark.parametrize("path", [".git", "a/.GIT", "__pycache__/x", "x/.hook-repro"])
def test_rt3_07_sidecar_with_reserved_vcs_path_refused(fake, tmp_path, path):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    assert hookc("build", "--git", r, *TC_ARM, "--out", tmp_path / "o") == 0
    d = load(tmp_path / "o" / "0.hook.metadata.json")
    d["source"]["vcs"]["path"] = path
    with pytest.raises(HC.HookcError, match="reserved component"):
        HC.parse_metadata(d)
    assert repro(save(tmp_path / "bad.json", d), r) == 3


# ---------------- R3-08: malformed inputs are UNVERIFIED (exit 3), never a traceback ----------------

def test_rt3_08_missing_reference_wasm_is_unverified(fake, tmp_path, capsys):
    # r3_08_crash_paths.sh (a): --wasm /nonexistent.wasm -> FileNotFoundError traceback, exit 1
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    assert hookc("build", "--git", r, *TC_ARM, "--out", tmp_path / "o") == 0
    m = str(tmp_path / "o" / "0.hook.metadata.json")
    assert repro(m, r, "--wasm", tmp_path / "nonexistent.wasm") == 3
    out = capsys.readouterr().out
    assert "VERDICT: UNVERIFIED" in out and "cannot read reference wasm" in out


@pytest.mark.parametrize("value", ["not-an-object", None, 7, ["x"]])
def test_rt3_08_non_object_platforms_entry_is_unverified(fake, tmp_path, value):
    # r3_08 (b): builder.platforms["linux/arm64"] = "not-an-object" -> AttributeError traceback, exit 1
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    assert hookc("build", "--git", r, *TC_ARM, "--out", tmp_path / "o") == 0
    d = load(tmp_path / "o" / "0.hook.metadata.json")
    d["builder"]["platforms"]["linux/arm64"] = value
    bad = save(tmp_path / "b.json", d)
    assert repro(bad, r) == 3
    assert repro(bad, r, *ARM) == 3


@pytest.mark.parametrize("change", ["drop", "extra"])
def test_guard_08_platforms_must_be_exactly_the_toolchain_twins(fake, tmp_path, change):
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    assert hookc("build", "--git", r, *TC_ARM, "--out", tmp_path / "o") == 0
    d = load(tmp_path / "o" / "0.hook.metadata.json")
    if change == "drop":
        del d["builder"]["platforms"]["linux/amd64"]
    else:
        d["builder"]["platforms"]["linux/riscv64"] = dict(d["builder"]["platforms"]["linux/arm64"])
    with pytest.raises(HC.HookcError, match="exactly the toolchain's twins"):
        HC.parse_metadata(d)


# ---------------- R3-09: HookCallbackFee absent/None handled per SetHook.cpp @bb244ef:1873-1881 ----------------

def defn_reads(**fields):
    node = {k: v for k, v in fields.items() if v is not None}
    return [{"definition": dict(node)}, {"definition": dict(node)}]


def _cbak_row(wce, defn):
    rows = {r["definition"]: r for r in V.definition_check({"WCE": wce}, defn_reads(**defn))["fields"]}
    assert rows["Fee"]["match"] is True and rows["HookCallbackFee"]["enforced"] is True
    return rows["HookCallbackFee"]["match"]


@pytest.mark.parametrize("wce,defn,match", [
    ({"hook": 20, "cbak": 5}, {"Fee": "20"}, False),                          # cbak > 0 but no field: MISMATCH
    ({"hook": 20, "cbak": 0}, {"Fee": "20", "HookCallbackFee": "0"}, False),  # SetHook never writes 0
    ({"hook": 20, "cbak": 0}, {"Fee": "20"}, True),                           # absent == WCE.cbak 0
])
def test_rt3_09_hookcallbackfee_compared_including_absence(wce, defn, match):
    assert _cbak_row(wce, defn) is match


@pytest.mark.parametrize("wce,defn,match", [
    ({"hook": 20, "cbak": 0}, {"Fee": "20", "HookCallbackFee": "5"}, False),
    ({"hook": 20, "cbak": 5}, {"Fee": "20", "HookCallbackFee": "6"}, False),
    ({"hook": 20, "cbak": 5}, {"Fee": "20", "HookCallbackFee": "5"}, True),
])
def test_guard_09_present_hookcallbackfee_compared(wce, defn, match):
    assert _cbak_row(wce, defn) is match


def test_rt3_09_absent_fee_is_a_mismatch_not_skipped():
    rows = {r["definition"]: r for r in V.definition_check({"WCE": {"hook": 20, "cbak": 0}}, defn_reads())["fields"]}
    assert rows["Fee"]["match"] is False and rows["Fee"]["definition_value"] == "(absent)"


def test_guard_09_null_wce_is_not_compared_and_said_so():
    rows = V.definition_check({"WCE": {"hook": None, "cbak": None}}, defn_reads(Fee="20", HookCallbackFee="5"))["fields"]
    assert [r["match"] for r in rows[:2]] == [None, None]
    assert "Fee/HookCallbackFee not compared (sidecar WCE is null)" in V.definition_summary(rows)


def test_rt3_09_verify_cbak_wce_without_chain_field_is_mismatch(sim, tmp_path, monkeypatch):
    # end to end: the sidecar says the module has a callback costing 7; the chain's definition has none
    monkeypatch.setattr(HC, "run_wce", lambda w, log=None: ({"hook": 20, "cbak": 7}, None))
    r = mkrepo(tmp_path / "repo", {"hook.c": HOOK_C})
    assert hookc("build", "--git", r, *TC_ARM, "--out", tmp_path / "o") == 0
    m = str(tmp_path / "o" / "0.hook.metadata.json")
    h = stub_chain(monkeypatch, (tmp_path / "o" / "0.hook.wasm").read_bytes())  # Fee 20, no HookCallbackFee
    assert verify(h, m, "--git", r, "--out", tmp_path / "v") == 2
    assert "HookCallbackFee (absent) != WCE.cbak 7" in load(tmp_path / "v" / "verify-report.json")["reason"]

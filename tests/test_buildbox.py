"""buildbox-2026-10: the live Hooks Builder remote compiler (hook-buildbox.xrpl.org), matched 2026-10-06.

Expected values are literal (recorded), never computed from the package under test.
The docker rebuild test is opt-in: HOOK_REPRO_DOCKER_TESTS=1.
"""
import hashlib
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from hook_repro import build as B  # noqa: E402

FX = os.path.join(os.path.dirname(__file__), "fixtures", "buildbox")
R = "buildbox-2026-10"

# Recorded from the live service 2026-10-06 (tests/fixtures/buildbox/README.md).
REMOTE = {
    "starter": "efc92b600dad8b8ef7bb5eeb52e078f0f04a2d191b2aa921e7e0933a5dfff51e",
    "firewall": "da187cc9b3aeeb03a3df6ca3e8cf8a811c7b963bb62fe3c1b48bf2099e5223ec",
    "blacklist": "a0524bfc481c477bc987f798ce4259e988130c75aa6572393fdaa54d14592984",
}


def sha(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def test_recipe_digest_is_pinned():
    assert B.recipe_digest(B.load_recipe(R)) == "8da93100b630d594e1b282f230cf8ae322d9a1082f2b1f2196287d96105c9d4b"


def test_xhc_bin127_digest_unchanged():
    # the old recipe keeps its identity; its stale presets are marked in code (PRESET_NOTES), not in recipe.json
    assert B.recipe_digest(B.load_recipe("xhc-bin127")) == \
        "13455c906e3c01aca7a51973acac2600cc34393582e7a3dddeb8fa33f2256b81"


def test_same_pinned_binaries_and_headers_as_xhc_bin127():
    a, b = B.load_recipe(R), B.load_recipe("xhc-bin127")
    assert a["base_image"] == b["base_image"]
    assert [(x["name"], x["sha256"], x["into"]) for x in a["artifacts"]] == \
        [(x["name"], x["sha256"], x["into"]) for x in b["artifacts"]]
    assert {x["name"]: x["sha256"] for x in a["artifacts"]}["wasm-opt"] == \
        "36f78112c8d629e27f8c68be89bee47c245cbde8794e1ff56c03212c02dc8484"


def test_params_are_fixed_to_the_server_settings():
    r = B.load_recipe(R)
    assert B.resolve_params(r, None, R) == {"CLANG_OPT": "-O3", "WASMOPT": "builder2025", "STAGES": "opt,clean"}
    assert B.resolve_params(r) == {"CLANG_OPT": "-O3", "WASMOPT": "builder2025", "STAGES": "opt,clean"}
    for k, v in (("CLANG_OPT", "-O2"), ("WASMOPT", "-O2"), ("STAGES", "opt,clean,opt")):
        with pytest.raises(B.BuildError):
            B.resolve_params(r, {k: v})


def test_pipeline_puts_tc_on_path_for_the_clang_driver():
    s = open(os.path.join(B.RECIPES_DIR, R, "pipeline.sh")).read()
    assert 'PATH=/tc:$PATH $S/bin/clang -Wno-builtin-macro-redefined "$D1" "$D2" "$D3" $CLANG_FLAGS -- "$@"' in s
    assert '$CLANG_FLAGS -- "$@"' in s and "$SOURCES" not in s
    # the xhc-bin127 pipeline does not (that is the difference that made it miss)
    t = open(os.path.join(B.RECIPES_DIR, "xhc-bin127", "pipeline.sh")).read()
    assert "PATH=/tc" not in t


def test_old_presets_are_marked_not_matching():
    for p in ("builder-2025", "builder-2026-07"):
        assert "does not match the live Hooks Builder" in B.preset_note("xhc-bin127", p)
        assert "buildbox-2026-10" in B.preset_note("xhc-bin127", p)
    assert B.preset_note("xhc-bin127", "classic") is None
    assert B.preset_note(R, R) is None


DRIVER_CLANG = (
    'for a in "$@"; do [ "$a" = "-###" ] && { [ -n "${FAKE_NO_DRIVER_OPT:-}" ] || '
    'echo " \\"$FAKE_LOG_DIR/tc/wasm-opt\\" \\"out.wasm\\" \\"-O3\\"" >&2; exit 0; }; done\n'  # run_pipeline re-roots /tc
)


def _run(tmp_path, monkeypatch, **env):
    import test_rt_round3 as R3
    monkeypatch.setitem(R3.FAKE_TOOLS, "clang", DRIVER_CLANG + R3.FAKE_TOOLS["clang"])
    return R3.run_pipeline(R, tmp_path, {"hook.c": b"int x;\n"}, CLANG_OPT="-O3", WASMOPT="builder2025",
                           STAGES="opt,clean", **env)


def test_pipeline_records_the_driver_wasm_opt(tmp_path, monkeypatch):
    rc, log, runs = _run(tmp_path, monkeypatch)
    assert rc == 0 and runs == 1  # the explicit pass; the driver's own run is the fake's -### line
    assert "HOOKC_WASM_OPT_RAN=1" in log
    line = [x for x in log.splitlines() if x.startswith("(clang driver, after wasm-ld) ")]
    assert len(line) == 1 and line[0].endswith("/tc/wasm-opt <out> -O3 -o <out>")  # /tc is re-rooted here


def test_pipeline_refuses_when_driver_would_not_run_wasm_opt(tmp_path, monkeypatch):
    rc, log, _ = _run(tmp_path, monkeypatch, FAKE_NO_DRIVER_OPT="1")
    assert rc == 4 and log is None


def test_fixtures_are_the_recorded_bytes():
    for n, h in REMOTE.items():
        assert sha(os.path.join(FX, n + ".remote.wasm")) == h


@pytest.mark.skipif(os.environ.get("HOOK_REPRO_DOCKER_TESTS") != "1", reason="docker rebuild is opt-in")
@pytest.mark.parametrize("name", sorted(REMOTE))
def test_docker_rebuild_matches_live_service(name, tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / (name + ".c")).write_bytes(open(os.path.join(FX, name + ".c"), "rb").read())
    hr = os.path.join(os.path.dirname(__file__), "..", "hook-repro")
    r = subprocess.run([hr, "build", str(src), "--recipe", R, "--preset", R, "--out", str(tmp_path / "o")],
                       capture_output=True, text=True, timeout=1800)
    assert r.returncode == 0, r.stderr[-2000:]
    assert sha(tmp_path / "o" / "hook.wasm") == REMOTE[name]

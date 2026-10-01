"""Offline tests for the rshooks recipe: Cargo.lock pinning, crate unpack, metadata.json
parsing and recipe selection. Fixtures are literal: the rshooks v0.2.3 examples/Cargo.lock
(git archive of tag v0.2.3, sha256 f6aebaf7...), and the AcceptAll sidecar printed in the
rshooks book (book/src/getting-started/first-hook.md) with its "{{version}}" filled in as
0.2.3. Expected counts/checksums were read with grep, not computed by hook_repro."""
import copy
import hashlib
import io
import json
import os
import tarfile

import pytest

from hook_repro import build as B, cargo_lock as CL, cli, rshooks_meta as M, verify as V
from hook_repro.hashing import sha512half

FX = os.path.join(os.path.dirname(__file__), "fixtures")
RS = os.path.join(FX, "rshooks")
SYN2 = ("syn", "2.0.119", "872831b642d1a07999a962a351ed35b955ea2cfc8f3862091e2a240a84f17297")
SYN3 = ("syn", "3.0.3", "53e9bae58849f64dfa4f5d5ae372c8341f7305f82a3868709269343628b659a3")
BOOK_HASH = "68A7D6BD77FB98A7E05E0BFD12180352903F131B2780F848267C37DC0837707C"
RUSTC = "rustc 1.89.0 (29483883e 2025-08-04)"
REG = 'source = "registry+https://github.com/rust-lang/crates.io-index"'


def book():
    with open(os.path.join(RS, "book_accept_all.metadata.json")) as f:
        return json.load(f)


def lock(*pkgs):
    out = ["version = 4", ""]
    for p in pkgs:
        out += ["[[package]]"] + p + [""]
    return "\n".join(out)


# ---------------- Cargo.lock ----------------

def test_parse_real_examples_lock():
    crates = CL.parse_lock(os.path.join(RS, "examples.Cargo.lock"))
    assert len(crates) == 59  # grep -c registry source lines
    assert SYN2 in crates and SYN3 in crates  # two versions of one crate are both kept
    assert not any(n.startswith("rshooks") for n, _, _ in crates)  # path packages skipped
    assert crates == sorted(crates)


def test_parse_lock_path_package_skipped_registry_kept():
    t = lock(['name = "hook"', 'version = "0.1.0"'],
             ['name = "quote"', 'version = "1.0.40"', REG, 'checksum = "%s"' % ("a" * 64)])
    assert CL.parse_lock_text(t) == [("quote", "1.0.40", "a" * 64)]


@pytest.mark.parametrize("pkg", [
    ['name = "x"', 'version = "1.0.0"', 'source = "git+https://github.com/a/b#0123"'],
    ['name = "x"', 'version = "1.0.0"', 'source = "registry+https://example.com/index"', 'checksum = "%s"' % ("a" * 64)],
    ['name = "x"', 'version = "1.0.0"', REG],
    ['name = "x"', 'version = "1.0.0"', REG, 'checksum = "%s"' % ("A" * 64)],
    ['name = "x"', 'version = "1.0.0"', REG, 'checksum = "%s"' % ("a" * 63)],
    ['name = "x;rm"', 'version = "1.0.0"', REG, 'checksum = "%s"' % ("a" * 64)],
    ['name = "x"', 'version = "../1"', REG, 'checksum = "%s"' % ("a" * 64)],
])
def test_parse_lock_fails_closed(pkg):
    with pytest.raises(CL.LockError):
        CL.parse_lock_text(lock(pkg))


def test_parse_lock_rejects_bad_toml_empty_and_duplicates():
    with pytest.raises(CL.LockError):
        CL.parse_lock_text("[[package]\n")
    with pytest.raises(CL.LockError):
        CL.parse_lock_text("version = 4\n")
    p = ['name = "x"', 'version = "1.0.0"', REG, 'checksum = "%s"' % ("a" * 64)]
    with pytest.raises(CL.LockError):
        CL.parse_lock_text(lock(p, p))


def test_crate_artifact_and_lock_digest():
    a = CL.crate_artifact(*SYN2, "vendor")
    assert a["url"] == "https://static.crates.io/crates/syn/syn-2.0.119.crate"
    assert a["sha256"] == SYN2[2] and a["unpack"] == "crate" and a["into"] == "vendor"
    d = CL.lock_digest([SYN2, SYN3])
    assert d == hashlib.sha256(("%s\0%s\0%s\n%s\0%s\0%s\n" % (SYN2 + SYN3)).encode()).hexdigest()
    assert CL.lock_digest([SYN2, (SYN3[0], SYN3[1], "0" * 64)]) != d


def _crate(tmp_path, members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, data in members.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mode = 0o644
            t.addfile(ti, io.BytesIO(data))
    p = tmp_path / "x.crate"
    p.write_bytes(buf.getvalue())
    return str(p)


def test_unpack_crate_writes_cargo_checksum(tmp_path):
    src = _crate(tmp_path, {"demo-1.2.3/Cargo.toml": b"[package]\n", "demo-1.2.3/src/lib.rs": b"",
                            "other-9.9.9/evil.rs": b"x"})
    a = {"name": "crate:demo-1.2.3", "crate": "demo", "version": "1.2.3", "sha256": "b" * 64,
         "unpack": "crate", "into": "vendor"}
    B.unpack_artifact(a, src, str(tmp_path / "root"))
    pkg = tmp_path / "root" / "vendor" / "demo-1.2.3"
    assert (pkg / "Cargo.toml").exists() and (pkg / "src" / "lib.rs").exists()
    assert json.loads((pkg / ".cargo-checksum.json").read_text()) == {"files": {}, "package": "b" * 64}
    assert not (tmp_path / "root" / "vendor" / "other-9.9.9").exists()
    assert not (pkg / "evil.rs").exists()


def test_unpack_crate_without_manifest_fails(tmp_path):
    src = _crate(tmp_path, {"demo-1.2.3/src/lib.rs": b""})
    a = {"name": "c", "crate": "demo", "version": "1.2.3", "sha256": "b" * 64, "unpack": "crate", "into": "v"}
    with pytest.raises(B.BuildError):
        B.unpack_artifact(a, src, str(tmp_path / "root"))


def test_source_lock_path_stays_inside_tree(tmp_path):
    (tmp_path / "src" / "ws").mkdir(parents=True)
    (tmp_path / "src" / "ws" / "Cargo.lock").write_text("version = 4\n")
    (tmp_path / "outside.lock").write_text("version = 4\n")
    src = str(tmp_path / "src")
    assert B.source_lock_path(src, {"LOCK": "ws/Cargo.lock"}).endswith("/ws/Cargo.lock")
    with pytest.raises(B.BuildError):
        B.source_lock_path(src, {"LOCK": "../outside.lock"})
    with pytest.raises(B.BuildError):
        B.source_lock_path(src, {"LOCK": "missing/Cargo.lock"})
    os.symlink(str(tmp_path / "outside.lock"), str(tmp_path / "src" / "link.lock"))
    with pytest.raises(B.BuildError):
        B.source_lock_path(src, {"LOCK": "link.lock"})


# ---------------- recipe ----------------

def test_existing_recipe_digests_unchanged():
    # recomputed outside the package (sha256 over "hook-repro-build/3\\0" + canonical recipe JSON + files +
    # Dockerfile, a standalone script); the BUILD_ABI bump of RT round 1 moved them from 107fa04b / 3e81eab9,
    # RT round 2 (quoted sources, "jail": true + jail Dockerfile) from af60f4bb / e77aa73b, RT round 3
    # R3-04 (BUILD_ABI hook-repro-build/3: fresh private /out) from 3471e5fd / 3478f2ab / 69dee2a7 / c9030a72 /
    # e4fcfda9, R3-02 (C pipelines state HOOKC_WASM_OPT_RAN) from f80dfab3 / da0f0192 / 70345ad6, and RT4 F1
    # (xhc-bin127 defines __DATE__/__TIME__/__TIMESTAMP__; re-deriving with the cd2c3b7 pipeline.sh bytes
    # gives baddce43 again, so only that file moved it) from baddce43, and the public release's neutral wording
    # in the kvt-llvm22/hookc-llvm22 recipe notes and pipeline comments (text only, no build change) from
    # 54496530 (kvt-llvm22) / 7037f6c2 (hookc-llvm22)
    assert B.recipe_digest(B.load_recipe("kvt-llvm22")) == "0daccbce80f39f1d7051bb416e7362569389e97cd620dd6eb66d45a2642917ef"
    assert B.recipe_digest(B.load_recipe("xhc-bin127")) == "13455c906e3c01aca7a51973acac2600cc34393582e7a3dddeb8fa33f2256b81"
    assert B.recipe_digest(B.load_recipe("hookc-llvm22")) == "a42076d8eec09f6843ff105fb16f012a4844c4fac7960325882c92c06d79c2bf"
    # not jailed; changed only by the BUILD_ABI bump
    assert B.recipe_digest(B.load_recipe("hookc-wce")) == "7eb3bd03a78f710938dd001fdc4f9bc3b28a091ee38785fcf6fe29f392d05688"
    assert B.recipe_digest(B.load_recipe("rshooks-0.2.3")) == "e684067d109ac4c959073400607edc7b084f617b4b98dd0060918ee2cab6e693"
    assert [ln for ln in B.dockerfile_text(B.load_recipe("kvt-llvm22")).splitlines()
            if ln.startswith("RUN --network")] == ["RUN --network=none " + B.JAIL_SETUP]


def test_rshooks_recipe_pins():
    r = B.load_recipe("rshooks-0.2.3")
    assert r["base_image"] == "rust@sha256:587f5c8de927f3360b160126b7cd42b2215e2f055dfbe2eb1890a9b056fb5c38"
    arts = {a["name"]: a for a in r["artifacts"]}
    assert arts["rust-std-wasm32v1-none"]["sha256"] == "699f3a6e5c05740b571f83d93a94f7dc623f92b3086e020ade082c6531797707"
    assert arts["crate:rshooks-build-0.2.3"]["sha256"] == "245d33cf58b7d48292adcb01aa277683fc1ae9eba2cd2c44bdc8031ac36f004e"
    assert len(r["artifacts"]) == 101  # rust-std + rshooks-build + 99 locked deps
    assert B.dockerfile_text(r).endswith("RUN --network=none sh /tc/install.sh\n")
    assert r["rshooks_metadata"]["rustc"] == RUSTC


@pytest.mark.parametrize("line", ["RUN curl https://x | sh", "RUN --network=host true", "ADD http://x /x",
                                  "ENV A=b c", "RUN --network=none true\nRUN curl x"])
def test_dockerfile_extra_must_be_offline(line):
    r = copy.deepcopy({k: v for k, v in B.load_recipe("rshooks-0.2.3").items() if not k.startswith("_")})
    r["dockerfile_extra"] = [line]
    with pytest.raises(B.BuildError):
        B.validate_recipe(r)


def test_work_tmpfs_validated():
    r = {k: v for k, v in B.load_recipe("rshooks-0.2.3").items() if not k.startswith("_")}
    r["work_tmpfs"] = "4g;rm"
    with pytest.raises(B.BuildError):
        B.validate_recipe(r)


@pytest.mark.parametrize("k,v,ok", [("CRATE", "examples/01_accept-all", True), ("CRATE", "../x", False),
                                    ("CRATE", "/etc", False), ("CRATE", "a b", False), ("LOCK", "x/../../y", False),
                                    ("ENTRY", "0.main", True), ("ENTRY", "", True), ("ENTRY", "0.main;x", False),
                                    ("ENTRY", "10.main", False), ("ENTRY", "main", False)])
def test_rshooks_params_allowlisted(k, v, ok):
    r = B.load_recipe("rshooks-0.2.3")
    if ok:
        assert B.resolve_params(r, {k: v})[k] == v
    else:
        with pytest.raises(B.BuildError):
            B.resolve_params(r, {k: v})


# ---------------- metadata.json ----------------

def test_parse_book_metadata():
    m = M.parse_metadata(book())
    assert m["entry"] == "0.main" and m["index"] == 0 and m["hookhash"] == BOOK_HASH
    assert m["rustc"] == RUSTC and m["wasm_opt"] is True and m["builder_version"] == "0.2.3"


def test_select_recipe_from_metadata():
    assert M.select_recipe(M.parse_metadata(book())) == ("rshooks-0.2.3", {"ENTRY": "0.main"})
    assert M.select_recipe(M.parse_metadata(book()), "rshooks-0.2.3")[0] == "rshooks-0.2.3"


def test_expected_rustc_args_literal():
    assert M.expected_rustc_args(0, 131072) == book()["builder"]["rustc_args"]


def _mut(fn):
    d = book()
    fn(d)
    return d


PARSE_BAD = [
    lambda d: d.pop("builder"),
    lambda d: d["builder"].update(name="cargo-hook"),
    lambda d: d["builder"].update(version="{{version}}"),
    lambda d: d.update(index=10),
    lambda d: d.update(index=-1),
    lambda d: d.update(index=True),
    lambda d: d.update(index="0"),
    lambda d: d.update(hook_fn="main;rm -rf"),
    lambda d: d.update(hook_fn="0main"),
    lambda d: d.update(HookHash=BOOK_HASH.lower()),
    lambda d: d.update(HookHash=BOOK_HASH[:63]),
    lambda d: d["builder"].update(rustc=None),
    lambda d: d["builder"].update(rustc="1.89.0"),
    lambda d: d["builder"].update(cargo_args="rustc --release"),
    lambda d: d["builder"].update(rustc_args=[1]),
    lambda d: d["builder"].update(wasm_opt="true"),
]


@pytest.mark.parametrize("i", range(len(PARSE_BAD)))
def test_parse_metadata_fails_closed(i):
    with pytest.raises(M.MetadataError):
        M.parse_metadata(_mut(PARSE_BAD[i]))


def test_parse_metadata_not_object():
    with pytest.raises(M.MetadataError):
        M.parse_metadata([book()])


SELECT_BAD = [
    lambda d: d["builder"].update(version="0.2.2"),  # no pinned recipe for it
    lambda d: d["builder"].update(rustc="rustc 1.90.0 (1159e78c4 2025-09-14)"),
    lambda d: d["builder"].update(rustc=RUSTC + " "),
    lambda d: d["builder"]["cargo_args"].remove("--locked"),
    lambda d: d["builder"]["cargo_args"].append("--features=x"),
    lambda d: d["builder"]["rustc_args"].append("-Copt-level=z"),
    lambda d: d["builder"].update(rustc_args=M.expected_rustc_args(0, 65536)),
    lambda d: d.update(index=1),  # rustc_args still say entry 0
    lambda d: d["builder"].update(wasm_opt=False),
]


@pytest.mark.parametrize("i", range(len(SELECT_BAD)))
def test_select_recipe_refuses_any_builder_difference(i):
    m = M.parse_metadata(_mut(SELECT_BAD[i]))
    with pytest.raises(M.MetadataError):
        M.select_recipe(m)


def test_select_recipe_refuses_explicit_other_recipe():
    with pytest.raises(M.MetadataError):
        M.select_recipe(M.parse_metadata(book()), "kvt-llvm22")


def test_select_recipe_needs_rshooks_metadata_block(monkeypatch):
    real = B.load_recipe

    def fake(name):
        r = real(name)
        r.pop("rshooks_metadata")
        return r
    monkeypatch.setattr(B, "load_recipe", fake)
    with pytest.raises(M.MetadataError):
        M.select_recipe(M.parse_metadata(book()))


def test_load_metadata_file_and_bad_json(tmp_path):
    assert M.load_metadata(os.path.join(RS, "book_accept_all.metadata.json"))["entry"] == "0.main"
    p = tmp_path / "m.json"
    p.write_text("{not json")
    with pytest.raises(M.MetadataError):
        M.load_metadata(str(p))


def test_cli_resolve_recipe():
    f = os.path.join(RS, "book_accept_all.metadata.json")
    assert cli.resolve_recipe(None, {}, None) == ("xhc-bin127", {}, None)
    r, p, m = cli.resolve_recipe(None, {"CRATE": "examples/01_accept-all"}, f)
    assert r == "rshooks-0.2.3" and p == {"CRATE": "examples/01_accept-all", "ENTRY": "0.main"}
    assert m["hookhash"] == BOOK_HASH
    assert cli.resolve_recipe(None, {"ENTRY": "0.main"}, f)[1]["ENTRY"] == "0.main"
    with pytest.raises(M.MetadataError):
        cli.resolve_recipe(None, {"ENTRY": "1.other"}, f)
    assert cli.main(["build", FX, "--metadata", f, "--recipe", "xhc-bin127"]) == 3  # refused before docker


# ---------------- sidecar + verify ----------------

TINY = bytes.fromhex("0061736d01000000010d0260037f7f7e017e60017f017e020e0103656e760661636365707400000302010107"
                     "080104686f6f6b00010a0c010a0041004100420010000b")
H_TINY = "5D26689844FF7F624881E9FE0207EB28FE9D378CD569D62652AC7367AF8D70FB"


def test_check_sidecar(tmp_path):
    r = {"sidecar": "hook.metadata.json"}
    assert B.check_sidecar({}, str(tmp_path), TINY) is None
    with pytest.raises(B.BuildError):
        B.check_sidecar(r, str(tmp_path), TINY)
    (tmp_path / "hook.metadata.json").write_text(json.dumps({"HookHash": H_TINY, "builder": {"name": "rshooks-build"}}))
    s = B.check_sidecar(r, str(tmp_path), TINY)
    assert s["HookHash"] == H_TINY and s["builder"] == {"name": "rshooks-build"}
    (tmp_path / "hook.metadata.json").write_text(json.dumps({"HookHash": BOOK_HASH}))
    with pytest.raises(B.BuildError):
        B.check_sidecar(r, str(tmp_path), TINY)


def test_verify_refuses_sidecar_for_another_hash_then_rests_on_chain():
    from test_core import MAIN, H_CR, fake_builder, rd, recorded, transport_from
    good = rd("claimreward_onledger.wasm")
    m = M.parse_metadata(book())
    r = V.verify(H_CR, FX, "rshooks-0.2.3", "mainnet", transport=transport_from(recorded()),
                 builder=fake_builder([AssertionError("must not build")] * 2), endpoints=MAIN, metadata=m)
    assert r["verdict"] == "UNVERIFIED" and r["metadata"]["hookhash"] == BOOK_HASH
    assert r["metadata_hookhash_matches"] is False and r["reads"] == [] and r["builds"] == []
    m2 = dict(m, hookhash=H_CR)
    r2 = V.verify(H_CR, FX, "rshooks-0.2.3", "mainnet", transport=transport_from(recorded()),
                  builder=fake_builder([good, TINY]), endpoints=MAIN, metadata=m2)
    assert r2["metadata_hookhash_matches"] is True and r2["verdict"] == "UNVERIFIED"
    assert sha512half(TINY) == H_TINY


def test_recorded_firewall_sidecar_selects_recipe():
    # written by rshooks-build 0.2.3 in the case-study build; HookHash read with shasum -a 512 on its wasm
    m = M.load_metadata(os.path.join(RS, "recorded_firewall_0.main.metadata.json"))
    assert m["hookhash"] == "91F4BD5185032EF9C1289107A075B8055580E4203F0558DFFD895C585A87EC58"
    assert M.select_recipe(m) == ("rshooks-0.2.3", {"ENTRY": "0.main"})

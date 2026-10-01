"""Generate hook_repro/recipes/rshooks-<version>/recipe.json from a downloaded
rshooks-build .crate (whose sha256 must equal the crates.io checksum passed in).

Every dependency of the rshooks-build CLI becomes a sha256-pinned artifact taken from
the crate's own Cargo.lock, so the image build (RUN --network=none) installs the CLI
with `cargo install --locked --offline` from nothing but pinned inputs.

usage: python3 tools/gen_rshooks_recipe.py <rshooks-build-X.Y.Z.crate> <crates.io sha256>
"""
import hashlib
import io
import json
import os
import sys
import tarfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hook_repro import cargo_lock  # noqa: E402

RUST_IMAGE = "rust@sha256:587f5c8de927f3360b160126b7cd42b2215e2f055dfbe2eb1890a9b056fb5c38"
RUSTC = "rustc 1.89.0 (29483883e 2025-08-04)"
RUST_STD = {"name": "rust-std-wasm32v1-none",
            "url": "https://static.rust-lang.org/dist/2025-08-07/rust-std-1.89.0-wasm32v1-none.tar.xz",
            "sha256": "699f3a6e5c05740b571f83d93a94f7dc623f92b3086e020ade082c6531797707",
            "unpack": "tar",
            "strip_prefix": "rust-std-1.89.0-wasm32v1-none/rust-std-wasm32v1-none/lib/rustlib/wasm32v1-none/",
            "into": "tc/rustlib-wasm32v1-none"}
PATH_PAT = r"^(?!.*\.\.)(?!/)[A-Za-z0-9_./-]+$"


def main(crate_path, want_sha):
    data = open(crate_path, "rb").read()
    got = hashlib.sha256(data).hexdigest()
    if got != want_sha:
        sys.exit("crate sha256 %s != %s" % (got, want_sha))
    base = os.path.basename(crate_path)[:-len(".crate")]
    version = base[len("rshooks-build-"):]
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        lock = t.extractfile("%s/Cargo.lock" % base).read().decode()
    deps = cargo_lock.parse_lock_text(lock)
    arts = [RUST_STD, cargo_lock.crate_artifact("rshooks-build", version, want_sha, "tc")]
    arts += [cargo_lock.crate_artifact(n, v, s, "tc/vendor") for n, v, s in deps]
    recipe = {
        "name": "rshooks-%s" % version,
        "summary": ("tequdev/rshooks Rust Hooks: rshooks-build %s (crates.io, cargo install --locked --offline "
                    "from %d sha256-pinned crates) on rustc 1.89.0 wasm32v1-none; hook crate deps vendored "
                    "from the source's own Cargo.lock; cargo --locked --offline, SOURCE_DATE_EPOCH=0, "
                    "--remap-path-prefix." % (version, len(deps))),
        "platform": "linux/arm64",
        "base_image": RUST_IMAGE,
        "base_image_note": "docker.io/library/rust:1.89.0-bookworm linux/arm64/v8 manifest (index "
                           "sha256:948f9b08a66e7fe01b03a98ef1c7568292e07ec2e4fe90d88c07bb14563c84ff); "
                           "ships rustc/cargo 1.89.0 and g++ 12 (binaryen inside wasm-opt-sys is C++).",
        "artifacts": arts,
        "vendored": ["install.sh"],
        "pipeline": "pipeline.sh",
        "dockerfile_extra": ["RUN --network=none sh /tc/install.sh"],
        "work_tmpfs": "4g",
        "timeout": 5400,
        "source_vendor": "cargo-lock",
        "sidecar": "hook.metadata.json",
        "params": {
            "CRATE": {"default": ".", "allowed_pattern": PATH_PAT},
            "LOCK": {"default": "Cargo.lock", "allowed_pattern": PATH_PAT},
            "ENTRY": {"default": "", "allowed_pattern": r"^([0-9]\.[A-Za-z_][A-Za-z0-9_]{0,63})?$"},
        },
        "presets": {"default": {}},
        "rshooks_metadata": {
            "version": version, "rustc": RUSTC,
            "cargo_args": ["rustc", "--release", "--locked", "--target", "wasm32v1-none", "--crate-type", "cdylib"],
            "stack_size": 131072, "wasm_opt": True},
        "tool_versions": {
            "rustc": RUSTC + " (image toolchain 1.89.0-aarch64-unknown-linux-gnu; wasm32v1-none rust-std sha256-pinned)",
            "cargo": "cargo 1.89.0 (c24e10642 2025-06-23)",
            "rshooks-build": "%s crates.io sha256 %s (bundles binaryen via wasm-opt 0.116.1 and xahaud Guard.h)"
                             % (version, want_sha),
        },
    }
    out = os.path.join(os.path.dirname(__file__), "..", "hook_repro", "recipes", recipe["name"], "recipe.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(recipe, f, indent=1)
        f.write("\n")
    print("wrote %s (%d artifacts)" % (out, len(arts)))


if __name__ == "__main__":
    main(*sys.argv[1:3])

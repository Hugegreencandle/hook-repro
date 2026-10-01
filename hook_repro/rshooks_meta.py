"""rshooks-build `<index>.<fn>.metadata.json` sidecar -> recipe + params.

rshooks-build (tequdev/rshooks) writes one sidecar per built Hook entry. Its `builder`
block records rshooks-build's version, `rustc -V`, the cargo and rustc arguments, and
whether the wasm-opt pass ran. This module maps that block onto a pinned hook-repro
recipe named `rshooks-<version>`. The recipe declares, in `rshooks_metadata`, the exact
builder values it reproduces, and ANY difference is refused (no nearest-match).
"""
import json
import re

from . import build as buildmod

ENTRY_FN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
HASH_RE = re.compile(r"^[0-9A-F]{64}$")
MAX_INDEX = 9  # rshooks' --check-cfg declares rshooks_entry values "0".."9"


class MetadataError(buildmod.BuildError):
    pass


def expected_rustc_args(index, stack_size):
    vals = ",".join('"%d"' % i for i in range(MAX_INDEX + 1))
    return ["--cfg", 'rshooks_entry="%d"' % index, "--check-cfg", "cfg(rshooks_entry,values(%s))" % vals,
            "-C", "link-arg=-zstack-size=%d" % stack_size]


def parse_metadata(doc):
    """Validate a sidecar dict; return the fields hook-repro uses."""
    if not isinstance(doc, dict):
        raise MetadataError("metadata.json is not an object")
    b = doc.get("builder")
    if not isinstance(b, dict):
        raise MetadataError("metadata.json has no builder block")
    if b.get("name") != "rshooks-build":
        raise MetadataError("builder.name %r is not rshooks-build" % b.get("name"))
    ver = b.get("version")
    if not isinstance(ver, str) or not VERSION_RE.match(ver):
        raise MetadataError("builder.version %r is not a release version" % ver)
    idx = doc.get("index")
    if type(idx) is not int or not 0 <= idx <= MAX_INDEX:
        raise MetadataError("index %r out of range 0..%d" % (idx, MAX_INDEX))
    fn = doc.get("hook_fn")
    if not isinstance(fn, str) or not ENTRY_FN_RE.match(fn):
        raise MetadataError("hook_fn %r is not a Rust identifier" % fn)
    hh = doc.get("HookHash")
    if not isinstance(hh, str) or not HASH_RE.match(hh):
        raise MetadataError("HookHash %r is not 64 uppercase hex" % hh)
    rustc = b.get("rustc")
    if not isinstance(rustc, str) or not rustc.startswith("rustc "):
        raise MetadataError("builder.rustc %r was not recorded" % rustc)
    for k in ("cargo_args", "rustc_args"):
        if not isinstance(b.get(k), list) or not all(isinstance(x, str) for x in b[k]):
            raise MetadataError("builder.%s is not a list of strings" % k)
    if not isinstance(b.get("wasm_opt"), bool):
        raise MetadataError("builder.wasm_opt is not a bool")
    return {"builder_version": ver, "index": idx, "hook_fn": fn, "hookhash": hh, "rustc": rustc,
            "cargo_args": list(b["cargo_args"]), "rustc_args": list(b["rustc_args"]),
            "wasm_opt": b["wasm_opt"], "entry": "%d.%s" % (idx, fn)}


def load_metadata(path):
    with open(path) as f:
        try:
            doc = json.load(f)
        except ValueError as e:
            raise MetadataError("metadata.json is not JSON: %s" % e)
    return parse_metadata(doc)


def select_recipe(meta, recipe_name=None):
    """Return (recipe_name, params) for a parsed sidecar. The recipe must pin exactly the
    builder the sidecar records."""
    want = "rshooks-%s" % meta["builder_version"]
    if recipe_name and recipe_name != want:
        raise MetadataError("metadata was built by rshooks-build %s; recipe %s cannot reproduce it"
                            % (meta["builder_version"], recipe_name))
    if want not in buildmod.list_recipes():
        raise MetadataError("no pinned recipe %s for this metadata (have: %s)"
                            % (want, ", ".join(buildmod.list_recipes())))
    r = buildmod.load_recipe(want)
    pin = r.get("rshooks_metadata")
    if not isinstance(pin, dict):
        raise MetadataError("recipe %s does not declare rshooks_metadata" % want)
    if meta["builder_version"] != pin["version"]:
        raise MetadataError("recipe %s pins rshooks-build %s" % (want, pin["version"]))
    if meta["rustc"] != pin["rustc"]:
        raise MetadataError("toolchain mismatch: metadata rustc %r, recipe %s pins %r"
                            % (meta["rustc"], want, pin["rustc"]))
    if meta["cargo_args"] != pin["cargo_args"]:
        raise MetadataError("cargo_args %r differ from the recipe's %r" % (meta["cargo_args"], pin["cargo_args"]))
    if meta["rustc_args"] != expected_rustc_args(meta["index"], pin["stack_size"]):
        raise MetadataError("rustc_args %r are not the recipe's entry-%d args" % (meta["rustc_args"], meta["index"]))
    if meta["wasm_opt"] is not pin["wasm_opt"]:
        raise MetadataError("wasm_opt=%s is not supported by recipe %s" % (meta["wasm_opt"], want))
    return want, {"ENTRY": meta["entry"]}

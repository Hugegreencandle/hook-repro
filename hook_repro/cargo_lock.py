"""Cargo.lock -> sha256-pinned crate artifacts -> an offline `directory` vendor tree.

Every crates.io package in a Cargo.lock carries `checksum`, the sha256 of its .crate
file. That makes the lockfile itself a complete pin list: each crate is fetched from
static.crates.io, checked against that sha256, and unpacked with a
`.cargo-checksum.json` so cargo can build `--offline --locked` from it.

Fail-closed: git sources, other registries, a registry package without a checksum, and
malformed names/versions are refused rather than skipped.
"""
import hashlib
import json
import os
import re
import tomllib

CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
CRATE_URL = "https://static.crates.io/crates/{n}/{n}-{v}.crate"
NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class LockError(ValueError):
    pass


def parse_lock_text(text):
    """Return [(name, version, sha256)] for every crates.io package, sorted.
    Path packages (no `source`) are local source and are skipped."""
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise LockError("Cargo.lock is not valid TOML: %s" % e)
    pkgs = doc.get("package")
    if not isinstance(pkgs, list):
        raise LockError("Cargo.lock has no [[package]] entries")
    out = []
    for p in pkgs:
        name, ver, src = p.get("name", ""), p.get("version", ""), p.get("source")
        if not NAME_RE.match(name) or not VERSION_RE.match(ver):
            raise LockError("bad package name/version %r %r" % (name, ver))
        if src is None:
            continue
        if src != CRATES_IO:
            raise LockError("package %s %s has unsupported source %r (only crates.io is pinned)" % (name, ver, src))
        cs = p.get("checksum", "")
        if not SHA_RE.match(cs):
            raise LockError("package %s %s has no sha256 checksum" % (name, ver))
        out.append((name, ver, cs))
    out.sort()
    if len(set((n, v) for n, v, _ in out)) != len(out):
        raise LockError("duplicate package entries in Cargo.lock")
    return out


def parse_lock(path):
    with open(path, "rb") as f:
        return parse_lock_text(f.read().decode("utf-8"))


def crate_artifact(name, version, sha, into):
    return {"name": "crate:%s-%s" % (name, version), "url": CRATE_URL.format(n=name, v=version),
            "sha256": sha, "unpack": "crate", "crate": name, "version": version, "into": into}


def lock_digest(crates):
    """sha256 over the sorted (name, version, sha256) list: identity of a vendor set."""
    h = hashlib.sha256()
    for n, v, s in crates:
        h.update(("%s\0%s\0%s\n" % (n, v, s)).encode())
    return h.hexdigest()


def write_checksum(pkg_dir, sha):
    """cargo `directory` sources need .cargo-checksum.json; an empty `files` map skips
    per-file checks, while `package` is the crate's verified sha256."""
    with open(os.path.join(pkg_dir, ".cargo-checksum.json"), "w") as f:
        json.dump({"files": {}, "package": sha}, f)

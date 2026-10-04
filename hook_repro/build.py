"""Hermetic hook builds: pinned recipe -> docker image -> --network none build -> manifest.

A recipe (hook_repro/recipes/<name>/recipe.json) names a base image BY DIGEST, every
downloaded artifact BY SHA-256, a pipeline script, and allowlisted parameters. The
recipe digest (sha256 over the canonical recipe JSON + pipeline + vendored files +
generated Dockerfile) is the portable toolchain identity; the local image ID is recorded
too but is not portable (docker layer metadata is not reproducible).

Local-cache trust (fail-closed): a CAS artifact is re-hashed every time it is used; a build
context is rebuilt from verified artifacts whenever an image must be built (no `.complete`
shortcut); a cargo vendor tree is re-derived from verified .crate artifacts on every use; and a
docker tag is used only if it is still bound to the image ID hook-repro recorded when it
built that image. The local docker daemon itself is trusted.

Source staging: the source is copied to a private staging dir WITHOUT TREE_IGNORE_DIRS
(`.git`, `__pycache__`, `.hook-repro` at any depth), the tree hash is computed over that
staging dir and only that dir is mounted (read-only), so source.tree_sha256 covers exactly
the source files the container receives. The container's /out is a fresh empty private dir
(never the caller's out dir); outputs are copied to the caller's out dir after the build.
Nothing else host-writable or pre-existing is mounted (hook-repro-build/3, RT3 R3-04).
"""
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import uuid
import zipfile

from . import cargo_lock
from .hashing import TREE_IGNORE_DIRS, sha256_file, sha512half, sha256_hex, tree_hash, tree_listing

RECIPES_DIR = os.path.join(os.path.dirname(__file__), "recipes")
CACHE = os.environ.get("HOOK_REPRO_CACHE", os.path.expanduser("~/.cache/hook-repro"))
MANIFEST_SCHEMA = "hook-repro/build-manifest/v1"
DOCKERFILE_EXTRA_RE = re.compile(r"^(RUN --network=none [^\n]+|ENV [A-Z_][A-Z0-9_]*=[^\s]+)$")
FIXED_ENV = {"SOURCE_DATE_EPOCH": "0", "TZ": "UTC", "LC_ALL": "C"}
# Version of the hook-repro code that turns a recipe into an image and a container run
# (Dockerfile generation, docker run flags, fixed env, source staging). It is part of every
# recipe digest, so a change in how hook-repro builds is a different toolchain identity.
BUILD_ABI = "hook-repro-build/3"


def portable_path(p):
    """A path as recorded in build manifests and verify reports. These files are evidence that gets
    published, so they must not carry the build host's absolute paths (user name, home layout): a path
    under the hook-repro cache is written as "$HOOK_REPRO_CACHE/...", one under the current directory
    relative to it, one under the home directory as "~/...", anything else as given (absolute). Paths
    are informational only: nothing reads them back to locate a file."""
    a = os.path.abspath(p)
    for base, label in ((os.path.abspath(CACHE), "$HOOK_REPRO_CACHE"), (os.getcwd(), None),
                        (os.path.expanduser("~"), "~")):
        if base in ("", os.sep):
            continue
        if a == base or a.startswith(base.rstrip(os.sep) + os.sep):
            rel = os.path.relpath(a, base)
            if label is None:
                return rel
            return label if rel == "." else label + "/" + rel.replace(os.sep, "/")
    return a


class BuildError(RuntimeError):
    pass


def list_recipes():
    return sorted(d for d in os.listdir(RECIPES_DIR)
                  if os.path.exists(os.path.join(RECIPES_DIR, d, "recipe.json")))


def load_recipe(name):
    if not re.match(r"^[A-Za-z0-9_.-]+$", name or ""):
        raise BuildError("bad recipe name %r" % name)
    path = os.path.join(RECIPES_DIR, name, "recipe.json")
    if not os.path.exists(path):
        raise BuildError("unknown recipe %r (have: %s)" % (name, ", ".join(list_recipes())))
    with open(path) as f:
        r = json.load(f)
    validate_recipe(r)
    r["_dir"] = os.path.dirname(path)
    return r


def validate_recipe(r):
    name = r.get("name")
    if not re.match(r"^[a-z0-9._/-]+@sha256:[0-9a-f]{64}$", r.get("base_image", "")):
        raise BuildError("recipe %s: base_image must be pinned by digest" % name)
    for a in r.get("artifacts", []):
        if not re.match(r"^[0-9a-f]{64}$", a.get("sha256", "")):
            raise BuildError("recipe %s: artifact %s lacks a sha256 pin" % (name, a.get("name")))
    for line in r.get("dockerfile_extra", []):
        # image-build steps may not reach the network: every input must be a pinned artifact
        if not DOCKERFILE_EXTRA_RE.match(line):
            raise BuildError("recipe %s: dockerfile_extra line %r must be RUN --network=none or ENV" % (name, line))
    if not re.match(r"^[0-9]{1,2}g$", r.get("work_tmpfs", "1g")):
        raise BuildError("recipe %s: bad work_tmpfs size" % name)
    if type(r.get("jail", False)) is not bool:
        raise BuildError("recipe %s: jail must be true or false" % name)


def resolve_params(recipe, params=None, preset=None):
    """Merge preset + explicit params over defaults; every value must be allowlisted
    (values reach a shell inside the container)."""
    spec = recipe.get("params", {})
    out = {k: v.get("default", "") for k, v in spec.items()}
    if preset:
        if preset not in recipe.get("presets", {}):
            raise BuildError("unknown preset %r for recipe %s" % (preset, recipe["name"]))
        out.update(recipe["presets"][preset])
    for k, v in (params or {}).items():
        if k not in spec:
            raise BuildError("unknown parameter %r for recipe %s" % (k, recipe["name"]))
        out[k] = v
    for k, v in out.items():
        s = spec[k]
        if "allowed" in s and v not in s["allowed"]:
            raise BuildError("parameter %s=%r not in allowlist %s" % (k, v, s["allowed"]))
        if "allowed_pattern" in s and not re.match(s["allowed_pattern"], v):
            raise BuildError("parameter %s=%r fails pattern" % (k, v))
    return out


# A "jail" recipe (the C toolchains) runs its pipeline in `chroot /jail`: a copy of the
# pinned base image's root file system made at image-build time WITHOUT /proc, /sys, /dev
# (only a /dev/null node), /tmp, /run, /home, /root and the build host's /etc/hostname,
# /etc/hosts, /etc/resolv.conf, with the toolchain at /jail/tc and headers at /jail/hdr.
# Docker cannot mask /proc (runc refuses any mount over or inside it), so the compiler is
# given a root in which /proc and /sys do not exist; /sys of the container is also a tmpfs.
# JAIL_ABI is part of the Dockerfile text, hence of every jail recipe's digest.
JAIL_ABI = "hook-repro-jail/1"
JAIL_SETUP = ("mkdir /jail && for d in /*; do case \"$d\" in /proc|/sys|/dev|/jail|/tmp|/run|/mnt|/media|/srv|"
              "/home|/root|/boot) ;; *) cp -a \"$d\" /jail/ ;; esac; done && mkdir -p /jail/dev /jail/tmp "
              "/jail/work /jail/src /jail/out /jail/vendor && mknod -m 666 /jail/dev/null c 1 3 && rm -f "
              "/jail/etc/hostname /jail/etc/hosts /jail/etc/resolv.conf /jail/etc/mtab")


def dockerfile_text(recipe):
    if recipe.get("jail"):
        lines = ["FROM %s" % recipe["base_image"], "# %s: pipeline runs in chroot /jail (no /proc, /sys)" % JAIL_ABI,
                 "RUN --network=none " + JAIL_SETUP, "COPY tc/ /jail/tc/"]
        if any(a["into"].startswith("hdr") for a in recipe["artifacts"]):
            lines.append("COPY hdr/ /jail/hdr/")
        lines.append("RUN chmod -R a+rX /jail/tc")
    else:
        lines = ["FROM %s" % recipe["base_image"], "COPY tc/ /tc/"]
        if any(a["into"].startswith("hdr") for a in recipe["artifacts"]):
            lines.append("COPY hdr/ /hdr/")
        lines.append("RUN chmod -R a+rX /tc")
    lines.extend(recipe.get("dockerfile_extra", []))
    return "\n".join(lines) + "\n"


def recipe_digest(recipe):
    """Portable toolchain identity."""
    h = hashlib.sha256()
    h.update(BUILD_ABI.encode() + b"\0")
    canon = {k: v for k, v in recipe.items() if not k.startswith("_")}
    h.update(json.dumps(canon, sort_keys=True, separators=(",", ":")).encode())
    for fn in [recipe["pipeline"]] + list(recipe.get("vendored", [])):
        with open(os.path.join(recipe["_dir"], fn), "rb") as f:
            h.update(b"\0" + fn.encode() + b"\0" + hashlib.sha256(f.read()).digest())
    h.update(dockerfile_text(recipe).encode())
    return h.hexdigest()


# ---------- artifacts ----------

def _cas_path(sha):
    return os.path.join(CACHE, "cas", sha)


def fetch_artifact(a, log=print):
    """Download (or reuse) an artifact; verify sha256 (also of a cached copy, on every use);
    return its CAS path."""
    dst = _cas_path(a["sha256"])
    if os.path.exists(dst):
        if sha256_file(dst) == a["sha256"]:
            return dst
        log("cached %s does not hash to its pin; discarding it" % a["name"])
        os.unlink(dst)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    local = os.path.join(CACHE, "dl", os.path.basename(a["url"]))
    if os.path.exists(local) and sha256_file(local) == a["sha256"]:
        os.link(local, dst)
        return dst
    log("fetching %s" % a["url"])
    tmp = dst + ".part"
    req = urllib.request.Request(a["url"], headers={"user-agent": "hook-repro/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=600) as r, open(tmp, "wb") as f:
            shutil.copyfileobj(r, f, 1 << 20)
    except OSError as e:  # URLError, HTTPError, timeouts
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise BuildError("artifact %s download failed: %s" % (a["name"], e))
    got = sha256_file(tmp)
    if got != a["sha256"]:
        os.unlink(tmp)
        raise BuildError("artifact %s sha256 %s != pinned %s" % (a["name"], got, a["sha256"]))
    os.rename(tmp, dst)
    return dst


def _selected(name, a):
    if any(name.startswith(p) for p in a.get("exclude_prefix", [])):
        return False
    inc = a.get("include_prefix")
    # include_prefix entries ending in "/" select a subtree; others select one exact member
    if inc and not any(name == p or (p.endswith("/") and name.startswith(p)) for p in inc):
        return False
    return name.startswith(a.get("strip_prefix", ""))


def unpack_artifact(a, src, dest_root):
    kind = a.get("unpack")
    into = os.path.join(dest_root, a["into"])
    sp = a.get("strip_prefix", "")
    if kind == "crate":
        # a crates.io .crate is a tar.gz whose members all live under <name>-<version>/
        base = "%s-%s" % (a["crate"], a["version"])
        sub = dict(a, unpack="tar", strip_prefix=base + "/", into=os.path.join(a["into"], base))
        unpack_artifact(sub, src, dest_root)
        pkg = os.path.join(dest_root, sub["into"])
        if not os.path.exists(os.path.join(pkg, "Cargo.toml")):
            raise BuildError("crate %s unpacked without Cargo.toml" % base)
        cargo_lock.write_checksum(pkg, a["sha256"])
        return
    if not kind:
        os.makedirs(os.path.dirname(into), exist_ok=True)
        shutil.copyfile(src, into)
        os.chmod(into, a.get("mode", 0o644))
        return
    os.makedirs(into, exist_ok=True)
    if kind == "zip":
        with zipfile.ZipFile(src) as z:
            for info in z.infolist():
                if not _selected(info.filename, a) or info.filename == sp:
                    continue
                rel = info.filename[len(sp):]
                out = os.path.join(into, rel)
                if info.is_dir():
                    os.makedirs(out, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(out), exist_ok=True)
                with z.open(info) as fi, open(out, "wb") as fo:
                    shutil.copyfileobj(fi, fo)
                mode = (info.external_attr >> 16) & 0o777
                os.chmod(out, mode or 0o644)
    elif kind in ("tar", "deb"):
        fobj = _deb_data(src) if kind == "deb" else None
        with (tarfile.open(fileobj=fobj, mode="r:*") if fobj else tarfile.open(src, "r:*")) as t:
            for m in t:
                if not _selected(m.name, a) or m.name.rstrip("/") + "/" == sp:
                    continue
                rel = m.name[len(sp):]
                out = os.path.join(into, rel)
                if m.isdir():
                    os.makedirs(out, exist_ok=True)
                elif m.issym():
                    os.makedirs(os.path.dirname(out), exist_ok=True)
                    if os.path.lexists(out):
                        os.unlink(out)
                    target = os.path.normpath(os.path.join(os.path.dirname(out), m.linkname))
                    if os.path.isabs(m.linkname) or not target.startswith(os.path.abspath(into) + os.sep):
                        raise BuildError("unsafe symlink %s -> %s" % (m.name, m.linkname))
                    os.symlink(m.linkname, out)
                elif m.isfile():
                    os.makedirs(os.path.dirname(out), exist_ok=True)
                    with t.extractfile(m) as fi, open(out, "wb") as fo:
                        shutil.copyfileobj(fi, fo)
                    os.chmod(out, m.mode & 0o777)
    else:
        raise BuildError("unknown unpack kind %r" % kind)


def _deb_data(path):
    """Return the data.tar.* member of a Debian .deb (ar archive) as a file object."""
    with open(path, "rb") as f:
        b = f.read()
    if b[:8] != b"!<arch>\n":
        raise BuildError("%s is not an ar/.deb archive" % path)
    i = 8
    while i + 60 <= len(b):
        name = b[i:i + 16].decode("ascii", "replace").strip().rstrip("/")
        size = int(b[i + 48:i + 58])
        if name.startswith("data.tar"):
            return io.BytesIO(b[i + 60:i + 60 + size])
        i += 60 + size + (size & 1)
    raise BuildError("%s has no data.tar member" % path)


def content_digest(root):
    """sha256 over every entry under root (files by content + exec bit, symlinks by target,
    directories by name). Used to detect a changed cache tree."""
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        rel_dir = os.path.relpath(dirpath, root)
        for n in sorted(dirnames + filenames):
            full = os.path.join(dirpath, n)
            rel = os.path.normpath(os.path.join(rel_dir, n)).encode("utf-8", "surrogateescape")
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                h.update(b"L" + rel + b"\0" + os.readlink(full).encode("utf-8", "surrogateescape") + b"\n")
            elif stat.S_ISDIR(st.st_mode):
                h.update(b"D" + rel + b"\n")
            elif stat.S_ISREG(st.st_mode):
                h.update(b"F" + rel + b"\0" + (b"x" if st.st_mode & 0o111 else b"-")
                         + sha256_file(full).encode() + b"\n")
            else:
                h.update(b"?" + rel + b"\n")
    return h.hexdigest()


def prepare_context(recipe, log=print):
    """Build a fresh docker build context from sha256-verified artifacts. Always rebuilt:
    it is only needed when an image has to be built, and a cached one is not trusted."""
    digest = recipe_digest(recipe)
    ctx = os.path.join(CACHE, "ctx", recipe["name"], digest[:16])
    if os.path.lexists(ctx):
        shutil.rmtree(ctx)
    os.makedirs(os.path.join(ctx, "tc"))
    for a in recipe["artifacts"]:
        src = fetch_artifact(a, log)
        log("unpacking %s" % a["name"])
        unpack_artifact(a, src, ctx)
    for fn in [recipe["pipeline"]] + list(recipe.get("vendored", [])):
        shutil.copyfile(os.path.join(recipe["_dir"], fn), os.path.join(ctx, "tc", fn))
    with open(os.path.join(ctx, "Dockerfile"), "w") as f:
        f.write(dockerfile_text(recipe))
    return ctx, digest


def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def docker_available():
    try:
        r = _run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


def _image_record_path(recipe, digest):
    return os.path.join(CACHE, "images", recipe["name"], digest + ".json")


def ensure_image(recipe, log=print):
    """Return the image for recipe. An existing tag is used only if it is still bound to the
    image ID hook-repro recorded when it built it; otherwise refused (fail closed)."""
    digest = recipe_digest(recipe)
    tag = "hook-repro/%s:%s" % (recipe["name"], digest[:16])
    rec_path = _image_record_path(recipe, digest)
    r = _run(["docker", "image", "inspect", "--format", "{{.Id}}", tag])
    if r.returncode == 0:
        have = r.stdout.strip()
        try:
            with open(rec_path) as f:
                rec = json.load(f)
        except (OSError, ValueError):
            rec = None
        if not isinstance(rec, dict) or rec.get("image_id") != have or rec.get("recipe_digest") != digest:
            raise BuildError("docker tag %s is bound to %s, which is not the image hook-repro recorded "
                             "building (%s); remove it (`docker image rm %s`) and rebuild"
                             % (tag, have, (rec or {}).get("image_id") if isinstance(rec, dict) else None, tag))
        return {"tag": tag, "image_id": have, "recipe_digest": digest}
    ctx, digest = prepare_context(recipe, log)
    log("docker build %s" % tag)
    r = _run(["docker", "build", "--platform", recipe["platform"], "-t", tag, ctx], timeout=3600)
    if r.returncode != 0:
        raise BuildError("docker build failed: %s" % r.stderr[-2000:])
    r = _run(["docker", "image", "inspect", "--format", "{{.Id}}", tag])
    if r.returncode != 0 or not r.stdout.strip():
        raise BuildError("docker image inspect %s failed after build" % tag)
    image_id = r.stdout.strip()
    os.makedirs(os.path.dirname(rec_path), exist_ok=True)
    with open(rec_path, "w") as f:
        json.dump({"tag": tag, "image_id": image_id, "recipe_digest": digest}, f)
    return {"tag": tag, "image_id": image_id, "recipe_digest": digest}


def source_lock_path(src_dir, params):
    """The source's Cargo.lock named by the LOCK param; must stay inside the source tree."""
    rel = params.get("LOCK") or "Cargo.lock"
    root = os.path.realpath(src_dir)
    path = os.path.realpath(os.path.join(root, rel))
    if not path.startswith(root + os.sep):
        raise BuildError("LOCK %r escapes the source tree" % rel)
    if not os.path.isfile(path):
        raise BuildError("LOCK %r not found in source tree" % rel)
    return path


def prepare_source_vendor(src_dir, params, log=print):
    """Fetch (sha256-pinned by the source's own Cargo.lock) and unpack every crates.io
    dependency into a `directory` vendor tree; returns (dir, info). The tree is keyed by the
    FULL lock digest and re-derived on every use from the sha256-verified CAS .crate files
    (which are re-hashed on every use): an existing tree, and any marker file next to it, is
    never trusted (RT5 P3), the same rule as a build context."""
    lock = source_lock_path(src_dir, params)
    crates = cargo_lock.parse_lock(lock)
    digest = cargo_lock.lock_digest(crates)
    info = {"lock": params.get("LOCK") or "Cargo.lock", "lock_sha256": sha256_file(lock),
            "vendor_digest": digest, "crates": [list(c) for c in crates]}
    root = os.path.join(CACHE, "vendor", digest)
    if os.path.lexists(root):
        shutil.rmtree(root)
    os.makedirs(os.path.join(root, "vendor"))
    for n, v, sha in crates:
        a = cargo_lock.crate_artifact(n, v, sha, "vendor")
        unpack_artifact(a, fetch_artifact(a, log), root)
    return os.path.join(root, "vendor"), info


def container_name(recipe):
    """A unique --name, so a timed-out or abandoned container can be killed by name."""
    return "hook-repro-%s-%s" % (recipe["name"], uuid.uuid4().hex[:12])


def kill_container(name):
    """Best effort: stop and remove a named container (killing the docker CLI client does not)."""
    for cmd in (["docker", "kill", name], ["docker", "rm", "-f", name]):
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            pass


def run_named(cmd, name, timeout):
    """subprocess.run(cmd) for a `docker run --name <name>` command. A timeout is a
    BuildError (never an uncaught TimeoutExpired), and on any abnormal exit (timeout,
    KeyboardInterrupt, crash) the container itself is killed, not just the client."""
    done = False
    try:
        r = _run(cmd, timeout=timeout)
        done = True
        return r
    except subprocess.TimeoutExpired:
        raise BuildError("container %s exceeded its %ss timeout; killed" % (name, timeout))
    finally:
        if not done:
            kill_container(name)


def run_container(recipe, image, src_dir, out_dir, params, timeout=None, vendor_dir=None):
    """One build in a fresh container: no network, read-only rootfs, tmpfs work dir. out_dir
    must be a FRESH EMPTY private directory (see _build_staged): whatever is in it is visible
    to the pipeline, so a non-empty one is refused."""
    if os.listdir(out_dir):
        raise BuildError("container output dir %s is not empty; the pipeline would see its contents" % out_dir)
    timeout = timeout or recipe.get("timeout", 900)
    name = container_name(recipe)
    j = "/jail" if recipe.get("jail") else ""
    cmd = ["docker", "run", "--rm", "--name", name, "--network", "none", "--platform", recipe["platform"],
           "--read-only", "--tmpfs", "%s/work:exec,size=%s" % (j, recipe.get("work_tmpfs", "1g")),
           "--tmpfs", "%s/tmp:exec,size=256m" % j,
           "-v", "%s:%s/src:ro" % (os.path.abspath(src_dir), j), "-v", "%s:%s/out" % (os.path.abspath(out_dir), j)]
    if j:
        cmd += ["--tmpfs", "/sys:ro,size=4k"]  # the container's own view of sysfs is empty too
    if vendor_dir:
        cmd += ["-v", "%s:%s/vendor:ro" % (os.path.abspath(vendor_dir), j)]
    for k, v in sorted({**FIXED_ENV, **params}.items()):
        cmd += ["-e", "%s=%s" % (k, v)]
    cmd += [image["image_id"]] + (["chroot", "/jail"] if j else []) + ["/bin/sh", "/tc/" + recipe["pipeline"]]
    r = run_named(cmd, name, timeout)
    if r.returncode != 0:
        raise BuildError("pipeline exit %d: %s" % (r.returncode, (r.stderr or r.stdout)[-2000:]))
    path = os.path.join(out_dir, "hook.wasm")
    if not os.path.exists(path):
        raise BuildError("pipeline produced no hook.wasm")
    with open(path, "rb") as f:
        return f.read()


def check_sidecar(recipe, out_dir, wasm):
    """A recipe that emits a builder sidecar (rshooks metadata.json) must emit one whose
    HookHash is the HookHash of the bytes it produced."""
    name = recipe.get("sidecar")
    if not name:
        return None
    path = os.path.join(out_dir, name)
    if not os.path.exists(path):
        raise BuildError("pipeline produced no %s" % name)
    with open(path) as f:
        doc = json.load(f)
    claimed = str(doc.get("HookHash", ""))
    if claimed != sha512half(wasm):
        raise BuildError("sidecar HookHash %s != built HookHash %s" % (claimed, sha512half(wasm)))
    return {"file": name, "sha256": sha256_file(path), "HookHash": claimed, "builder": doc.get("builder")}


def stage_source(src_dir, dest):
    """Copy src_dir to dest without TREE_IGNORE_DIRS (at any depth); symlinks and special
    files are refused. dest is exactly what the container receives."""
    root = os.path.abspath(src_dir)
    if not os.path.isdir(root):
        raise BuildError("not a directory: %s" % src_dir)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel = os.path.relpath(dirpath, root)
        out_dir = dest if rel == "." else os.path.join(dest, rel)
        os.makedirs(out_dir, exist_ok=True)
        for d in list(dirnames):
            if d in TREE_IGNORE_DIRS:
                dirnames.remove(d)
            elif os.path.islink(os.path.join(dirpath, d)):
                raise BuildError("symlinked directory in source tree: %s" % os.path.join(dirpath, d))
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            st = os.lstat(full)
            if not stat.S_ISREG(st.st_mode):
                raise BuildError("not a regular file in source tree: %s" % full)
            shutil.copyfile(full, os.path.join(out_dir, fn))
            os.chmod(os.path.join(out_dir, fn), 0o755 if st.st_mode & 0o111 else 0o644)
    return dest


def build(src_dir, recipe_name, params=None, preset=None, out_dir=None, log=print):
    """Build once, write hook.wasm + build-manifest.json to out_dir, return manifest."""
    recipe = load_recipe(recipe_name)
    p = resolve_params(recipe, params, preset)
    stage_root = tempfile.mkdtemp(prefix="hook-repro-stage-", dir=_tmp_dir())
    try:
        staged = stage_source(src_dir, os.path.join(stage_root, "src"))
        return _build_staged(recipe, p, src_dir, staged, out_dir, log)
    finally:
        shutil.rmtree(stage_root, ignore_errors=True)


def _tmp_dir():
    d = os.path.join(CACHE, "tmp")
    os.makedirs(d, exist_ok=True)
    return d


# Pre-scan (belt to the jail's braces): an include-like operand or asm .incbin naming an
# ABSOLUTE path reads a file of the build host, and one with a '..' component can climb out of
# /work/src into the jail's own root file system (per-arch base image: the twins could build
# different bytes) or, before hook-repro-build/3, into the container's /out. Lexical and
# best-effort: a macro-computed operand is not seen. The enforcement is the jail (no /proc,
# /sys) plus a fresh empty private /out and a read-only /src; the pre-scan only turns the
# plain spellings into an early, explained refusal.
_SPLICE = re.compile(rb"\\\r?\n")
_BLOCK_COMMENT = re.compile(rb"/\*.*?\*/", re.S)
_LINE_COMMENT = re.compile(rb"//[^\n]*")
OPERAND_RES = [
    re.compile(rb"^[ \t]*(?:#|%:)[ \t]*(?:include|include_next|import|embed)\b[ \t]*[\"<]([^\">\n]*)", re.M),
    re.compile(rb"__has_(?:include|include_next|embed)\s*\(\s*[\"<]([^\">\n]*)"),
    re.compile(rb"\.incbin[\s\\\"]*([^\s\\\"]*)"),
]


def unsafe_operand(op):
    """An include-like operand that is absolute or has a '..' component ('/' or '\\' separated)."""
    op = op.strip()
    return op.startswith(b"/") or b".." in re.split(rb"[/\\\\]", op)


def host_path_references(root):
    """[(relpath, operand)] for every file under root whose #include/#include_next/#import/
    #embed, __has_include/__has_include_next/__has_embed or asm .incbin operand is an absolute
    path or has a '..' component."""
    out = []
    for rel, _ in tree_listing(root):
        with open(os.path.join(root, rel), "rb") as f:
            text = f.read()
        text = _LINE_COMMENT.sub(b"", _BLOCK_COMMENT.sub(b" ", _SPLICE.sub(b"", text)))
        for rx in OPERAND_RES:
            for m in rx.finditer(text):
                if unsafe_operand(m.group(1)):
                    out.append((rel, m.group(0).decode("latin-1").strip()))
    return out


def out_inside(out_dir, *roots):
    """The first root that out_dir lies inside (or equals), else None. A build's outputs
    written into the directory it compiles would become source of the next build."""
    o = os.path.realpath(out_dir)
    for r in roots:
        if r:
            rr = os.path.realpath(r)
            if o == rr or o.startswith(rr.rstrip(os.sep) + os.sep):
                return r
    return None


def publish_outputs(private, out_dir):
    """Copy every file the pipeline wrote to the private out dir into out_dir, replacing a
    same-named entry (a stale file or planted symlink is replaced, never followed or read)."""
    os.makedirs(out_dir, exist_ok=True)
    for name in sorted(os.listdir(private)):
        src = os.path.join(private, name)
        if os.path.islink(src) or not os.path.isfile(src):
            raise BuildError("pipeline wrote a non-regular output %s" % name)
        fd, tmp = tempfile.mkstemp(prefix=".hook-repro-", dir=out_dir)
        with os.fdopen(fd, "wb") as fo, open(src, "rb") as fi:
            shutil.copyfileobj(fi, fo)
        os.chmod(tmp, 0o644)  # mkstemp creates 0600
        os.replace(tmp, os.path.join(out_dir, name))


def _build_staged(recipe, p, src_dir, staged, out_dir, log):
    if recipe.get("jail"):
        refs = host_path_references(staged)
        if refs:
            raise BuildError("source names an absolute or '..' path in an include-like operand (the build could "
                             "read outside its source): %s" % "; ".join("%s: %s" % r for r in refs[:8]))
    out_dir = out_dir or tempfile.mkdtemp(prefix="hook-repro-")
    if out_inside(out_dir, src_dir):
        raise BuildError("output dir %s lies inside the source %s; choose an --out outside it" % (out_dir, src_dir))
    th, listing = tree_hash(staged)
    vendor_dir, vendor = None, None
    if recipe.get("source_vendor") == "cargo-lock":
        vendor_dir, vendor = prepare_source_vendor(staged, p, log)
    image = ensure_image(recipe, log)
    # The container gets a FRESH EMPTY private /out, never out_dir: a pre-existing or reused
    # out dir (a previous run's outputs, files an attacker committed or planted there) would be
    # readable by the compiler. Outputs are copied to out_dir after the build.
    private = tempfile.mkdtemp(prefix="hook-repro-out-", dir=_tmp_dir())
    try:
        t0 = time.time()
        wasm = run_container(recipe, image, staged, private, p, vendor_dir=vendor_dir)
        th2, _ = tree_hash(staged)
        if th2 != th:
            raise BuildError("staged source changed during the build")
        sidecar = check_sidecar(recipe, private, wasm)
        log_txt = ""
        bt = os.path.join(private, "build.txt")
        if os.path.exists(bt):
            with open(bt) as f:
                log_txt = f.read()
        seconds = round(time.time() - t0, 1)
        publish_outputs(private, out_dir)
    finally:
        shutil.rmtree(private, ignore_errors=True)
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "recipe": {"name": recipe["name"], "digest": image["recipe_digest"],
                   "platform": recipe["platform"], "base_image": recipe["base_image"],
                   "artifacts": [{"name": a["name"], "url": a["url"], "sha256": a["sha256"]}
                                 for a in recipe["artifacts"]],
                   "tool_versions": recipe.get("tool_versions", {})},
        "image": image,
        "hook_repro": {"build_abi": BUILD_ABI},
        "params": p,
        "env": FIXED_ENV,
        "source": {"dir": portable_path(src_dir), "tree_sha256": th,
                   "files": [list(e) for e in listing]},
        "vendor": vendor,
        "sidecar": sidecar,
        "container_log": log_txt,
        "seconds": seconds,
        "output": {"file": portable_path(os.path.join(out_dir, "hook.wasm")), "size": len(wasm),
                   "sha256": sha256_hex(wasm), "sha512half": sha512half(wasm)},
    }
    with open(os.path.join(out_dir, "build-manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
    return manifest, wasm

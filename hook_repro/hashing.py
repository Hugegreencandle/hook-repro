"""Hashes: SHA512Half (Xahau HookHash), sha256, and a deterministic source-tree hash."""
import hashlib
import os

TREE_IGNORE_DIRS = {".git", "__pycache__", ".hook-repro"}


def sha512half(data):
    """Xahau HookHash = first 32 bytes of SHA-512 over CreateCode, uppercase hex."""
    return hashlib.sha512(bytes(data)).digest()[:32].hex().upper()


def sha256_hex(data):
    return hashlib.sha256(bytes(data)).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class TreeError(ValueError):
    pass


def tree_listing(root):
    """Sorted [(relpath, sha256)] of regular files under root. Symlinks are refused:
    a link's target is outside what the hash covers."""
    entries = []
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        raise TreeError("not a directory: %s" % root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for d in list(dirnames):
            full = os.path.join(dirpath, d)
            if d in TREE_IGNORE_DIRS:
                dirnames.remove(d)
            elif os.path.islink(full):
                raise TreeError("symlinked directory in source tree: %s" % full)
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            if os.path.islink(full):
                raise TreeError("symlink in source tree: %s" % full)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            entries.append((rel, sha256_file(full)))
    entries.sort(key=lambda e: e[0].encode("utf-8"))
    return entries


def listing_hash(listing):
    """sha256 over 'relpath\\0sha256\\n' for every (relpath, sha256); the listing must
    already be byte-sorted by path (tree_listing and hookc.export_tree sort it)."""
    h = hashlib.sha256()
    for rel, digest in listing:
        h.update(rel.encode("utf-8") + b"\0" + digest.encode() + b"\n")
    return h.hexdigest()


def tree_hash(root):
    """sha256 over 'relpath\\0sha256\\n' for every file, byte-sorted by path."""
    listing = tree_listing(root)
    return listing_hash(listing), listing

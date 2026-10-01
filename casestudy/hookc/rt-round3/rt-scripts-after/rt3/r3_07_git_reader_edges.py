"""R3-07: hookc's own git object reader (cat-file --batch + parse_tree + re-hash) on crafted objects,
compared with what git itself says. No docker. Prints hookc's result and git's view per case."""
import os, subprocess, sys, tempfile, shutil
HR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rt3-hookc")
sys.path.insert(0, HR)
from hook_repro import hookc as HC

def sh(repo, *a, inp=None):
    r = subprocess.run(["git", "-C", repo] + list(a), input=inp, capture_output=True)
    return r.returncode, r.stdout, r.stderr

def repo(fmt="sha1"):
    d = tempfile.mkdtemp(prefix="r3g-", dir=os.environ.get("W", None))
    subprocess.run(["git", "init", "-q", "--object-format=" + fmt, d], check=True)
    return d

def blob(r, data):
    return sh(r, "hash-object", "-w", "--stdin", inp=data)[1].decode().strip()

def raw_tree(r, entries, fmt="sha1"):
    body = b"".join(m.encode() + b" " + n + b"\0" + bytes.fromhex(o) for m, n, o in entries)
    return sh(r, "hash-object", "-w", "--literally", "-t", "tree", "--stdin", inp=body)[1].decode().strip()

def commit(r, tree, extra=b""):
    body = b"tree " + tree.encode() + b"\nauthor a <a@b> 0 +0000\ncommitter a <a@b> 0 +0000\n" + extra + b"\nm\n"
    return sh(r, "hash-object", "-w", "--literally", "-t", "commit", "--stdin", inp=body)[1].decode().strip()

def try_export(r, c, path=""):
    d = tempfile.mkdtemp(prefix="r3x-")
    try:
        info = HC.export_tree(r, c, path, os.path.join(d, "src"))
        return "ACCEPTED files=%s" % [n for n, _ in info["listing"]]
    except HC.HookcError as e:
        return "REFUSED: %s" % str(e)[:140]
    finally:
        shutil.rmtree(d, ignore_errors=True)

HOOK = b"int64_t hook(uint32_t r){return 0;}\n"
cases = []
r = repo(); a = blob(r, HOOK); b = blob(r, b"/*b*/\n")
t = raw_tree(r, [("100644", b"b.c", b), ("100644", b"a.c", a)])          # unsorted
c = commit(r, t); cases.append(("unsorted tree [b.c, a.c]", r, c, ""))
t = raw_tree(r, [("100644", b"a.c", a)]); sub = raw_tree(r, [("040000", b"d", t)])  # zero-padded dir mode
cases.append(("zero-padded 040000 dir", r, commit(r, sub), ""))
cases.append(("mode 100664 file", r, commit(r, raw_tree(r, [("100664", b"a.c", a)])), ""))
cases.append(("mode 40000 -> blob", r, commit(r, raw_tree(r, [("40000", b"a.c", a)])), ""))
cases.append(("mode 100644 -> tree", r, commit(r, raw_tree(r, [("100644", b"a.c", t)])), ""))
cases.append(("gitlink 160000", r, commit(r, raw_tree(r, [("100644", b"a.c", a), ("160000", b"m", "1" * 40)])), ""))
cases.append(("symlink 120000", r, commit(r, raw_tree(r, [("100644", b"a.c", a), ("120000", b"l", b)])), ""))
cases.append(("duplicate a.c", r, commit(r, raw_tree(r, [("100644", b"a.c", a), ("100644", b"a.c", b)])), ""))
cases.append(("commit with gpgsig + mergetag headers", r, commit(r, t, b"gpgsig -----BEGIN-----\n x\n -----END-----\nmergetag object 1\n"), ""))
dotgit = raw_tree(r, [("100644", b"a.c", a)]); top = raw_tree(r, [("40000", b".git", dotgit)])
cases.append(("vcs.path = '.git' (tree entry named .git)", r, commit(r, top), ".git"))
top2 = raw_tree(r, [("40000", b".GIT", dotgit)])
cases.append(("vcs.path = '.GIT'", r, commit(r, top2), ".GIT"))
cases.append(("hidden top-level .x.c", r, commit(r, raw_tree(r, [("100644", b".x.c", a), ("100644", b"a.c", a)])), ""))
cases.append(("300-byte name", r, commit(r, raw_tree(r, [("100644", b"x" * 298 + b".c", a)])), ""))
r2 = repo("sha256"); a2 = blob(r2, HOOK)
t2 = raw_tree(r2, [("100644", b"a.c", a2)]); cases.append(("sha256 repo", r2, commit(r2, t2), ""))
for name, rr, c, p in cases:
    fsck = sh(rr, "fsck", "--no-dangling", "--strict")[2].decode().strip().splitlines()
    rc, out, err = sh(rr, "archive", "--format=tar", c) if not p else sh(rr, "archive", "--format=tar", c + ":" + p)
    tarnames = subprocess.run(["tar", "-t"], input=out, capture_output=True).stdout.decode().split() if rc == 0 else ["archive rc=%d %s" % (rc, err.decode().strip()[:80])]
    print("== %s\n   hookc: %s\n   git archive: %s\n   git fsck: %s" % (name, try_export(rr, c, p), tarnames[:4], [l[:90] for l in fsck if c[:7] in l or "error" in l][:2]))

"""hookc: deterministic, metadata-emitting builds of Xahau Hooks written in C.

The C counterpart of rshooks-build's `<index>.<fn>.metadata.json`. hookc drives the pinned
hook-repro recipes (it does not duplicate them), builds every hook twice in fresh
`--network none` containers on every requested platform twin, refuses unless all builds
are byte-identical, and writes:

  <index>.hook.wasm            the deployable CreateCode
  <index>.hook.metadata.json   rshooks-compatible sidecar + a `source` provenance block

Metadata is platform-independent on purpose: it lists every pinned platform twin of the
toolchain, never the host, the time, or a host path, so two honest builds on different
machines emit byte-identical metadata.

Fail-closed rules:
  - a versioned build compiles ONLY the exact committed blobs of <commit>:<path>, exported
    from git objects (never the work tree), and source.tree_sha256 is computed from those
    git objects; `reproduce` / `verify --metadata` rebuild only from such an export of the
    sidecar's own commit/path, regenerate the ENTIRE sidecar (source block included) from
    what was actually built and byte-compare it;
  - the export refuses unsafe or colliding names (absolute, '..', '.', empty, '\\', control
    characters, '.git', the hashing ignore dirs, non-UTF-8, case-fold or NFC/NFD
    collisions), writes only under its destination, and re-lists what it wrote;
  - no git provenance (commit + tree) -> refused, unless --allow-unversioned, and metadata
    without provenance is refused by `reproduce` and `hook-repro verify --metadata`;
  - builds that differ (within or across platforms) -> refused, with a section diff;
  - a module xahaud's validateGuards rejects -> refused (it cannot be installed);
  - WCE is only ever the number validateGuards computed; if that tool cannot run the build
    is refused (no sidecar), and only an explicit --no-wce writes WCE null, with the one fixed,
    host-independent reason NO_WCE_REASON; `reproduce`/`verify` that cannot run the tool for a
    sidecar that states a WCE say UNVERIFIED (the tool failed; nothing was compared), never
    MISMATCH.
"""
import json
import os
import platform as _platform
import re
import shutil
import stat
import subprocess
import tempfile
import tomllib
import hashlib
import unicodedata

from . import build as buildmod
from .hashing import TREE_IGNORE_DIRS, listing_hash, sha256_hex, sha512half, tree_hash
from .wasm import WasmError, diff as wasm_diff, parse as wasm_parse

HOOKC_VERSION = "0.5.0"
BUILDER_NAME = "hookc"
WCE_RECIPE = "hookc-wce"
WCE_XAHAUD_COMMIT = "bb244ef7729503a0317bcff0f8fdaa93ca5cb7d2"
MAX_INDEX = 9
HASH_RE = re.compile(r"^[0-9A-F]{64}$")
MASK_RE = re.compile(r"^[0-9A-F]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")  # sha1 or sha256 object ids
REL_RE = re.compile(r"^(?:(?!\.\.?(?:/|$))[A-Za-z0-9_.-]+(?:/(?!\.\.?(?:/|$))[A-Za-z0-9_.-]+)*)?$")
ENTRY_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*\.c$")  # never a leading '-'

# Toolchains = families of pinned hook-repro recipes that must give identical bytes.
TOOLCHAINS = {
    "xhc-bin127": {
        "platforms": {"linux/amd64": "xhc-bin127"},
        "default_preset": "classic",
        "entry_param": None,
        "note": "xrpl-hooks-compiler v1.27 bin.zip ships x86_64 Linux binaries only; there is no arm64 twin.",
    },
    "hookc-llvm22": {
        "platforms": {"linux/arm64": "hookc-llvm22", "linux/amd64": "hookc-llvm22-amd64"},
        "default_preset": "deploy",
        "entry_param": "ENTRY",
        "note": "upstream LLVM/binaryen/wabt release binaries + official xahaud hook/*.h; both linux/arm64 and linux/amd64.",
    },
    "kvt-llvm22": {
        "platforms": {"linux/arm64": "kvt-llvm22", "linux/amd64": "kvt-llvm22-amd64"},
        "default_preset": "deploy",
        "entry_param": "ENTRY",
        "note": "upstream LLVM/binaryen/wabt release binaries exist for both linux/arm64 and linux/amd64.",
    },
}

# Xahau TransactionType codes, transcribed from xahaud hook/tts.h (the pinned copy in recipe
# xhc-bin127, xahaud @8bcebde). Same names and codes as rshooks-build 0.2.3 tx_type_table.rs.
TX_TYPES = {
    "Payment": 0, "EscrowCreate": 1, "EscrowFinish": 2, "AccountSet": 3, "EscrowCancel": 4,
    "SetRegularKey": 5, "OfferCreate": 7, "OfferCancel": 8, "TicketCreate": 10,
    "SignerListSet": 12, "PaymentChannelCreate": 13, "PaymentChannelFund": 14,
    "PaymentChannelClaim": 15, "CheckCreate": 16, "CheckCash": 17, "CheckCancel": 18,
    "DepositPreauth": 19, "TrustSet": 20, "AccountDelete": 21, "SetHook": 22,
    "NFTokenMint": 25, "NFTokenBurn": 26, "NFTokenCreateOffer": 27, "NFTokenCancelOffer": 28,
    "NFTokenAcceptOffer": 29, "Clawback": 30, "AMMClawback": 31, "AMMCreate": 35,
    "AMMDeposit": 36, "AMMWithdraw": 37, "AMMVote": 38, "AMMBid": 39, "AMMDelete": 40,
    "URITokenMint": 45, "URITokenBurn": 46, "URITokenBuy": 47, "URITokenCreateSellOffer": 48,
    "URITokenCancelSellOffer": 49, "XChainCreateClaimID": 50, "XChainCommit": 51,
    "XChainClaim": 52, "XChainAccountCreateCommit": 53, "XChainAddClaimAttestation": 54,
    "XChainAddAccountCreateAttestation": 55, "XChainModifyBridge": 56,
    "XChainCreateBridge": 57, "DIDSet": 58, "DIDDelete": 59, "OracleSet": 60,
    "OracleDelete": 61, "LedgerStateFix": 62, "MPTokenIssuanceCreate": 63,
    "MPTokenIssuanceDestroy": 64, "MPTokenIssuanceSet": 65, "MPTokenAuthorize": 66,
    "CredentialCreate": 67, "CredentialAccept": 68, "CredentialDelete": 69,
    "NFTokenModify": 70, "PermissionedDomainSet": 71, "PermissionedDomainDelete": 72,
    "Cron": 92, "CronSet": 93, "SetRemarks": 94, "Remit": 95, "GenesisMint": 96,
    "Import": 97, "ClaimReward": 98, "Invoke": 99, "EnableAmendment": 100, "SetFee": 101,
    "UNLModify": 102, "EmitFailure": 103, "UNLReport": 104,
}
SETHOOK_BIT = 22


class HookcError(buildmod.BuildError):
    pass


class WceUnavailable(HookcError):
    """The sidecar states a WCE but this run could not recompute it (--no-wce, or the pinned
    hookc-wce tool did not run): the claim is unchecked, which is UNVERIFIED, not MISMATCH."""


# The only builder.wce.reason a sidecar may carry, and only with WCE null (RT4 F3b): a reason
# written from a failed tool run embedded host-specific text (a local docker image id).
NO_WCE_REASON = "WCE not computed (--no-wce)"


# ---------------- declarations (HookOn / HookCanEmit / HookName) ----------------

def hook_mask(values):
    """Xahau's inverted tx-type mask for HookOn/HookCanEmit (xahaud applyHook.cpp canHook:
    field ^= bit[ttHOOK_SET]; field = ~field). None (omitted) -> None. Identical algorithm to
    rshooks-build metadata.rs hook_mask."""
    if values is None:
        return None
    b = bytearray(b"\xff" * 32)
    b[31 - SETHOOK_BIT // 8] ^= 1 << (SETHOOK_BIT % 8)
    for v in values:
        code = TX_TYPES[v]
        b[31 - code // 8] ^= 1 << (code % 8)
    return bytes(b).hex().upper()


def decode_mask(mask):
    """Inverse of hook_mask: the tx types a mask selects, in code order."""
    b = bytearray(bytes.fromhex(mask))
    b[31 - SETHOOK_BIT // 8] ^= 1 << (SETHOOK_BIT % 8)
    return [n for n, c in sorted(TX_TYPES.items(), key=lambda kv: kv[1])
            if not b[31 - c // 8] & (1 << (c % 8))]


def _tx_list(field, v):
    if v is None:
        return None
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise HookcError("%s must be a list of transaction type names" % field)
    seen = set()
    for x in v:
        if x not in TX_TYPES:
            raise HookcError("%s: unknown transaction type %r" % (field, x))
        if x in seen:
            raise HookcError("%s: duplicate transaction type %r" % (field, x))
        seen.add(x)
    return list(v)


def normalize_decls(d):
    """Validate declarations. Omitted keys keep rshooks' 'no installation override' meaning."""
    d = dict(d or {})
    unknown = set(d) - {"index", "name", "description", "on", "can_emit"}
    if unknown:
        raise HookcError("unknown declaration keys: %s" % ", ".join(sorted(unknown)))
    idx = d.get("index", 0)
    if type(idx) is not int or not 0 <= idx <= MAX_INDEX:
        raise HookcError("index %r out of range 0..%d" % (idx, MAX_INDEX))
    name = d.get("name")
    warnings = []
    if name is not None:
        # rshooks-build 0.2.3 carriers.rs: a HookName outside 2..=8 Unicode chars is an error;
        # entry_sidecar.rs: outside 4..=16 UTF-8 bytes is a warning. Same rules here.
        if not isinstance(name, str) or not 2 <= len(name) <= 8:
            raise HookcError("name (HookName) must be 2 to 8 Unicode characters (rshooks rule)")
        if not 4 <= len(name.encode()) <= 16:
            warnings.append("HookName %r is %d UTF-8 bytes; rshooks documents xahaud's 4..16 byte rule"
                            % (name, len(name.encode())))
    desc = d.get("description")
    if desc is not None and not isinstance(desc, str):
        raise HookcError("description must be a string")
    on = d.get("on")
    if on == "all":
        form, on_list = "all", None
    elif on is None:
        form, on_list = "omitted", None
    else:
        form, on_list = "list", _tx_list("on", on)
    return {"index": idx, "name": name, "description": desc, "on_form": form, "on": on_list,
            "can_emit": _tx_list("can_emit", d.get("can_emit"))}, warnings


def load_decls(path=None, overrides=None):
    d = {}
    if path:
        with open(path, "rb") as f:
            try:
                doc = tomllib.load(f)
            except tomllib.TOMLDecodeError as e:
                raise HookcError("declarations file %s: %s" % (path, e))
        if set(doc) - {"hook"}:
            raise HookcError("declarations file %s: only a [hook] table is allowed" % path)
        d = dict(doc.get("hook", {}))
    for k, v in (overrides or {}).items():
        if v is not None:
            d[k] = v
    return normalize_decls(d)


def parse_tx_arg(s):
    """CLI: 'all', '' (empty list = explicit none) or 'Payment,Invoke'."""
    if s is None:
        return None
    if s == "all":
        return "all"
    return [x.strip() for x in s.split(",") if x.strip()]


# ---------------- source provenance ----------------

# Every git call runs with replace objects off (flag AND env), in an environment scrubbed of
# every caller GIT_* variable (GIT_DIR, GIT_OBJECT_DIRECTORY, GIT_ALTERNATE_OBJECT_DIRECTORIES,
# GIT_CONFIG*, GIT_REPLACE_REF_BASE, GIT_CEILING_DIRECTORIES, ...), with no system or global
# config/attributes (HOME and XDG_CONFIG_HOME point at an empty private dir). Git is then only
# an object store: every object hookc uses (commit, every tree, every blob) is read raw and
# re-hashed to its id, and trees are parsed by hookc itself, so a replacement, graft or
# planted object can never stand in for the object the sidecar names.
_GIT_HOME = []


def _git_home():
    if not _GIT_HOME or not os.path.isdir(_GIT_HOME[0]):
        _GIT_HOME[:] = [tempfile.mkdtemp(prefix="hookc-git-home-")]
    return _GIT_HOME[0]


def git_env():
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("GIT_") and k not in ("HOME", "XDG_CONFIG_HOME", "EMAIL")}
    home = _git_home()
    env.update(HOME=home, XDG_CONFIG_HOME=home, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_ATTR_NOSYSTEM="1", GIT_NO_REPLACE_OBJECTS="1", GIT_TERMINAL_PROMPT="0",
               GIT_OPTIONAL_LOCKS="0", GIT_LITERAL_PATHSPECS="1", LC_ALL="C")
    return env


# Command-line config outranks every config file (including ones a repo includes), so these
# neutralise repo-local keys that could make the git commands hookc runs execute or read
# something else. Keys that cannot be neutralised this way are refused (git_config_check).
GIT_OVERRIDES = ("core.fsmonitor=false", "core.useReplaceRefs=false", "core.attributesFile=/dev/null", "core.sshCommand=false", "core.pager=cat",
                 "core.untrackedCache=false")


def git_cmd(repo, *args):
    cmd = ["git", "--no-replace-objects", "-C", repo]
    for kv in GIT_OVERRIDES:
        cmd += ["-c", kv]
    return cmd + list(args)


# Repository config keys hookc refuses (RT4 H1): filter drivers run commands when `git status`
# re-reads a file; includes pull in config hookc cannot see with --no-includes; core.worktree
# moves the work tree a --src/`build DIR` check reads. Matched case-insensitively on the key.
RISKY_CONFIG_RE = re.compile(r"^(?:filter\.|include\.|includeif\.|core\.worktree$)", re.I)


def git_config_check(repo):
    """Refuse (exit 3) a repository whose own config (local and per-worktree; system and global
    are off) sets a RISKY_CONFIG_RE key. Read with --no-includes: listing config runs nothing."""
    out = _git(repo, "config", "--list", "--no-includes", "--name-only", "-z", binary=True)
    bad = sorted({k.decode("utf-8", "replace") for k in out.split(b"\0")
                  if k and RISKY_CONFIG_RE.match(k.decode("utf-8", "replace"))})
    if bad:
        raise HookcError("git repository %s sets config hookc refuses (filter drivers, includes or core.worktree "
                         "can run commands or redirect the work tree): %s. Use a plain clone"
                         % (repo, ", ".join(bad[:8])))


def _git(repo, *args, binary=False, stdin=None):
    r = subprocess.run(git_cmd(repo, *args), capture_output=True, env=git_env(), input=stdin)
    if r.returncode != 0:
        raise HookcError("git %s failed: %s" % (" ".join(args), r.stderr.decode(errors="replace")[-400:]))
    return r.stdout if binary else r.stdout.decode().strip()


HASHES = {"sha1": (hashlib.sha1, 40), "sha256": (hashlib.sha256, 64)}


def git_repo_check(repo):
    """The repository's object format; refuses object-store indirections hookc does not
    follow: alternates (objects/info/alternates, http-alternates) and grafts (info/grafts).
    Replace refs and shallow boundaries need no refusal: replacement is off and every object
    is re-hashed, and history is never traversed (the commit is identified by its own
    re-hashed bytes)."""
    git_config_check(repo)
    fmt = _git(repo, "rev-parse", "--show-object-format")
    if fmt not in HASHES:
        raise HookcError("git repository %s has unsupported object format %r" % (repo, fmt))
    common = _git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir")
    for rel in ("objects/info/alternates", "objects/info/http-alternates", "info/grafts"):
        if os.path.lexists(os.path.join(common, rel)):
            raise HookcError("git repository %s uses %s (objects or history from outside the repository); "
                             "refusing. Use a plain clone." % (repo, rel))
    return fmt


def _cat_objects(repo, oids, fmt):
    """{oid: (type, bytes)} via one `git cat-file --batch`; each object is re-hashed with the
    repository's object format and must hash to the id it was requested by."""
    if not oids:
        return {}
    hfn, hexlen = HASHES[fmt]
    raw = _git(repo, "cat-file", "--batch", binary=True, stdin=("\n".join(oids) + "\n").encode())
    out, i = {}, 0
    for oid in oids:
        if len(oid) != hexlen:
            raise HookcError("git object id %r is not a %s id" % (oid, fmt))
        nl = raw.index(b"\n", i)
        head = raw[i:nl].decode(errors="replace").split()
        if len(head) != 3 or head[0] != oid or head[1] not in ("commit", "tree", "blob", "tag"):
            raise HookcError("git cat-file: unexpected header %r for %s" % (" ".join(head), oid))
        kind, size = head[1], int(head[2])
        data = raw[nl + 1:nl + 1 + size]
        if len(data) != size or raw[nl + 1 + size:nl + 2 + size] != b"\n":
            raise HookcError("git cat-file: truncated object %s" % oid)
        if hfn(b"%s %d\0" % (kind.encode(), size) + data).hexdigest() != oid:
            raise HookcError("git object %s does not hash to its id (replaced, planted or corrupt object); refusing"
                             % oid)
        out[oid] = (kind, data)
        i = nl + 2 + size
    return out


def _one(repo, oid, kind, fmt):
    got = _cat_objects(repo, [oid], fmt)[oid]
    if got[0] != kind:
        raise HookcError("git object %s is a %s, not a %s" % (oid, got[0], kind))
    return got[1]


def resolve_commit(repo, rev, fmt):
    """rev -> commit id, and the commit's root tree id parsed from its re-hashed raw bytes."""
    if not isinstance(rev, str) or not rev or rev.startswith("-"):
        raise HookcError("bad revision %r" % rev)
    commit = _git(repo, "rev-parse", "--verify", "--end-of-options", "%s^{commit}" % rev)
    data = _one(repo, commit, "commit", fmt)
    first = data.split(b"\n", 1)[0].decode(errors="replace").split(" ")
    if len(first) != 2 or first[0] != "tree" or len(first[1]) != HASHES[fmt][1]:
        raise HookcError("commit %s has no tree header" % commit)
    return commit, first[1]


def tree_sort_key(mode, name):
    """git's tree entry order (fsck treeNotSorted): byte order of the name, a tree compared as
    if its name ended in '/'."""
    return name + (b"/" if mode.lstrip("0") == "40000" else b"")


def parse_tree(data, fmt):
    """Raw git tree bytes -> [(mode, name_bytes, oid)]; refuses malformed or duplicate entries
    and entries out of git's own order (git fsck: treeNotSorted), which git itself never writes
    and different readers can list differently."""
    rawlen = HASHES[fmt][1] // 2
    out, seen, i, prev = [], set(), 0, None
    while i < len(data):
        sp, nul = data.find(b" ", i), data.find(b"\0", i)
        if sp < 0 or nul < 0 or sp > nul or nul + 1 + rawlen > len(data):
            raise HookcError("malformed git tree object")
        mode, name = data[i:sp].decode("ascii", "replace"), data[sp + 1:nul]
        if not name or b"/" in name or name in seen:
            raise HookcError("git tree has an invalid or duplicate entry name %r" % name)
        key = tree_sort_key(mode, name)
        if prev is not None and key <= prev:
            raise HookcError("git tree is not sorted (%r after %r; git fsck treeNotSorted); refusing" % (name, prev))
        prev = key
        seen.add(name)
        out.append((mode, name, data[nul + 1:nul + 1 + rawlen].hex()))
        i = nul + 1 + rawlen
    return out


def resolve_tree(repo, commit_tree, path, fmt):
    """The tree id at `path` under a root tree, walking re-hashed raw tree objects."""
    tree = commit_tree
    for comp in [c for c in (path or "").split("/") if c]:
        ents = {n: (m, o) for m, n, o in parse_tree(_one(repo, tree, "tree", fmt), fmt)}
        m, o = ents.get(comp.encode(), (None, None))
        if m != "40000":
            raise HookcError("%s is not a directory in tree %s" % (path, commit_tree))
        tree = o
    return tree


# gitattributes that make a checkout (what a reviewer reads, or passes as --src) differ from
# the blob hookc compiles. `-attr` / `!attr` (unset / unspecified) are harmless; `binary` is
# `-text -diff -merge`.
CONVERTING_ATTRS = ("ident", "filter", "eol", "text", "crlf", "working-tree-encoding", "export-subst")


def converting_attributes(text):
    """[(line, attribute)] for every line of a gitattributes file that sets (or gives a value
    to) one of CONVERTING_ATTRS, for any pattern (hookc does not evaluate which files a
    pattern matches: any such line refuses) and in `[attr]` macro definitions."""
    out = []
    for line in text.splitlines():
        ln = line.strip()
        if not ln or ln.startswith("#"):
            continue
        if ln.startswith('"'):  # C-quoted pattern
            end = ln.find('"', 1)
            while end > 0 and ln[end - 1] == "\\":
                end = ln.find('"', end + 1)
            rest = ln[end + 1:] if end > 0 else ""
        else:
            rest = ln.split(None, 1)[1] if len(ln.split(None, 1)) > 1 else ""
        for tok in rest.split():
            name = tok.split("=", 1)[0]  # "-attr" / "!attr" never equal an attribute name
            if name in CONVERTING_ATTRS:
                out.append((line, name))
    return out


def check_attributes(repo, root_tree, path, subtree_ents, fmt, where):
    """Refuse (exit 3) a source whose .gitattributes (in any directory from the repository root
    down to and inside the exported path) or the repository's info/attributes would convert
    files on checkout (ident, filter, eol/text/crlf, working-tree-encoding, export-subst):
    hookc compiles the exact blobs, so a reviewer reading a checkout would read other text."""
    attr_blobs, tree = [], root_tree
    comps = [c for c in (path or "").split("/") if c]
    for i in range(len(comps) + 1):
        ents = {n: (m, o) for m, n, o in parse_tree(_one(repo, tree, "tree", fmt), fmt)}
        if b".gitattributes" in ents:
            attr_blobs.append(("/".join(comps[:i] + [".gitattributes"]), ents[b".gitattributes"][1]))
        if i < len(comps):
            tree = ents[comps[i].encode()][1]
    attr_blobs += [(("%s/%s" % (path, n)) if path else n, o) for n, _, o in subtree_ents
                   if n == ".gitattributes" or n.endswith("/.gitattributes")]
    found = []
    for name, oid in dict(attr_blobs).items():
        text = _one(repo, oid, "blob", fmt).decode("utf-8", "replace")
        found += ["%s: %r sets %s" % (name, ln.strip(), a) for ln, a in converting_attributes(text)]
    local = os.path.join(_git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir"), "info", "attributes")
    if os.path.isfile(local):
        with open(local, encoding="utf-8", errors="replace") as f:
            found += ["$GIT_DIR/info/attributes: %r sets %s" % (ln.strip(), a) for ln, a in converting_attributes(f.read())]
    if found:
        raise HookcError("source %s: git attributes convert files on checkout, so a checkout differs from the "
                         "blobs hookc compiles; refusing. Review the committed bytes with `git show "
                         "<commit>:<path>`, remove the attribute, or commit without it. Found: %s"
                         % (where, "; ".join(found[:8])))


def walk_tree(repo, tree, fmt):
    """Every entry under tree as [(path_bytes, mode, oid)], every tree object re-hashed.
    Directories are descended; anything that is not a regular file or a directory is
    returned as-is for the caller to refuse."""
    out, level = [], [(b"", tree)]
    while level:
        objs = _cat_objects(repo, sorted({o for _, o in level}), fmt)
        nxt = []
        for prefix, oid in level:
            kind, data = objs[oid]
            if kind != "tree":
                raise HookcError("git object %s is a %s, not a tree" % (oid, kind))
            for mode, name, child in parse_tree(data, fmt):
                if mode == "40000":
                    nxt.append((prefix + name + b"/", child))
                else:
                    out.append((prefix + name, mode, child))
        level = nxt
    return out


def _fold(name):
    """Collision key: case-folded, Unicode-normalized (what a case-insensitive or
    normalization-insensitive filesystem may treat as the same name)."""
    return unicodedata.normalize("NFC", unicodedata.normalize("NFD", name).casefold())


# Characters refused in any exported path component: shell/glob metacharacters, quotes and
# backslash. With a leading '-', whitespace and non-printable characters also refused, no
# exported name can become a compiler flag or be split, globbed or expanded by a pipeline.
UNSAFE_NAME_CHARS = frozenset("*?[]{}$`'\"\\;&|<>()~!#%")


def safe_tree_name(raw, where="."):
    """A git tree path (bytes) -> str, or HookcError. Each component must be a plain,
    portable file name: no absolute/empty/./.. components, no leading '-', no whitespace,
    no shell/glob metacharacter or quote or backslash, no non-printable character, no .git
    (any case) and none of the hashing ignore dirs; valid UTF-8."""
    try:
        name = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise HookcError("source %s has a file name that is not valid UTF-8: %r" % (where, raw))
    for c in name.split("/"):
        if c in ("", ".", ".."):
            raise HookcError("source %s has an unsafe path %r (empty, '.' or '..' component)" % (where, name))
        if c.startswith("-") or any(ch in UNSAFE_NAME_CHARS or ch.isspace() or not ch.isprintable() for ch in c):
            raise HookcError("source %s has an unsafe path %r (leading '-', whitespace, shell/glob metacharacter, "
                             "quote, backslash or non-printable character)" % (where, name))
        if _fold(c) == ".git" or c in TREE_IGNORE_DIRS:
            raise HookcError("source %s has a reserved path component %r in %r" % (where, c, name))
    return name


def _check_collisions(names, where="."):
    seen = {}
    for name in names:
        parts = name.split("/")
        for i in range(1, len(parts) + 1):
            p = "/".join(parts[:i])
            other = seen.setdefault(_fold(p), p)
            if other != p:
                raise HookcError("source %s has paths %r and %r that collide on a case-insensitive or "
                                 "Unicode-normalizing filesystem; refusing" % (where, other, p))


def check_vcs_path(path):
    """source.vcs.path: a clean relative path with no '.git' (any case) and no hashing ignore
    dir in ANY component (the export never contains such names, so neither may the path to it)."""
    if not REL_RE.match(path or ""):
        raise HookcError("bad source path %r" % path)
    for c in (path or "").split("/"):
        if c and (_fold(c) == ".git" or c in TREE_IGNORE_DIRS):
            raise HookcError("source path %r has a reserved component %r (.git or an ignored dir)" % (path, c))


def export_tree(repo, rev, path, dest):
    """Write the exact committed blobs of <rev>:<path> into dest (no checkout, no eol or
    filter conversion) and return {"vcs", "listing", "tree_sha256", "file_count"}.
    tree_sha256 is computed from the git objects; after writing, dest is re-listed and must
    hold exactly those files with exactly those bytes."""
    check_vcs_path(path)
    fmt = git_repo_check(repo)
    commit, root_tree = resolve_commit(repo, rev, fmt)
    tree = resolve_tree(repo, root_tree, path or "", fmt)
    where = path or "."
    ents = []
    for name, mode, obj in walk_tree(repo, tree, fmt):
        if mode not in ("100644", "100755"):
            raise HookcError("source %s has %r (mode %s): only regular files are allowed" % (where, name, mode))
        ents.append((safe_tree_name(name, where), mode, obj))
    _check_collisions([n for n, _, _ in ents], where)
    check_attributes(repo, root_tree, path or "", ents, fmt, where)
    objs = _cat_objects(repo, sorted({o for _, _, o in ents}), fmt)
    blobs = {}
    for o, (kind, data) in objs.items():
        if kind != "blob":
            raise HookcError("git object %s is a %s, not a blob" % (o, kind))
        blobs[o] = data
    os.makedirs(dest, exist_ok=True)
    root = os.path.realpath(dest)
    if os.listdir(root):
        raise HookcError("export destination %s is not empty" % dest)
    listing = []
    for name, mode, obj in ents:
        _write_new(_dest_path(root, name), blobs[obj], 0o755 if mode == "100755" else 0o644)
        listing.append((name, hashlib.sha256(blobs[obj]).hexdigest()))
    listing.sort(key=lambda e: e[0].encode("utf-8"))
    written = _relist(root)
    if written != listing:
        raise HookcError("export of %s:%s wrote %d files that differ from the %d git blobs; refusing"
                         % (commit[:12], where, len(written), len(listing)))
    vcs = {"type": "git", "commit": commit, "path": path or "", "tree": tree, "dirty": False}
    return {"vcs": vcs, "listing": listing, "tree_sha256": listing_hash(listing), "file_count": len(listing)}


def _dest_path(root, name):
    """root/name, refusing anything that would land outside root (also via a symlinked
    parent). root must be a realpath."""
    out = os.path.join(root, *name.split("/"))
    if not os.path.normpath(out).startswith(root + os.sep):
        raise HookcError("source path %r escapes the export directory" % name)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    parent = os.path.realpath(os.path.dirname(out))
    if parent != root and not parent.startswith(root + os.sep):
        raise HookcError("source path %r escapes the export directory" % name)
    return out


def _write_new(path, data, mode):
    """Create path exclusively (never overwrite, never follow a symlink)."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    except OSError as e:
        raise HookcError("export cannot create %s exclusively: %s" % (path, e))
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _relist(root):
    """Every regular file under root (nothing skipped), as sorted [(relpath, sha256)]."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for n in dirnames + filenames:
            full = os.path.join(dirpath, n)
            if os.path.islink(full):
                raise HookcError("export produced a symlink: %s" % full)
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            with open(full, "rb") as f:
                out.append((os.path.relpath(full, root).replace(os.sep, "/"), hashlib.sha256(f.read()).hexdigest()))
    out.sort(key=lambda e: e[0].encode("utf-8"))
    return out


def export_git(repo, rev, path, dest):
    """export_tree, returning only the vcs block."""
    return export_tree(repo, rev, path, dest)["vcs"]


def worktree_location(src):
    """(toplevel, relpath) of a directory inside a git work tree, or (None, reason)."""
    try:
        _git(src, "rev-parse", "--git-dir")
    except (HookcError, OSError):
        return None, "not inside a git work tree"
    git_config_check(src)  # the repository src belongs to, before anything (git status) could honour it
    try:
        top = _git(src, "rev-parse", "--show-toplevel")
    except (HookcError, OSError):
        return None, "not inside a git work tree"
    rel = os.path.relpath(os.path.realpath(src), os.path.realpath(top)).replace(os.sep, "/")
    return (top, "" if rel == "." else rel), None


def vcs_of_dir(src):
    """Provenance of a plain directory: the git commit + tree it matches, if it is a clean
    subtree of a git work tree; else None and a reason. (A clean status is a usability
    guard: a versioned build still compiles the git export, never the work tree.)"""
    loc, why = worktree_location(src)
    if loc is None:
        return None, why
    top, rel = loc
    if _git(src, "status", "--porcelain", "--untracked-files=all", "--ignored=no", "--", "."):
        return None, "work tree has uncommitted or untracked changes under %s" % (rel or ".")
    fmt = git_repo_check(top)
    commit, root_tree = resolve_commit(top, "HEAD", fmt)
    tree = resolve_tree(top, root_tree, rel, fmt)
    return {"type": "git", "commit": commit, "path": rel, "tree": tree, "dirty": False}, None


def source_block(src, info, entry):
    """The metadata source block. Versioned: everything comes from the git export (info);
    unversioned: tree hash of the directory, vcs null."""
    if info is not None:
        return {"vcs": info["vcs"], "tree_sha256": info["tree_sha256"], "file_count": info["file_count"],
                "entry": entry}
    th, listing = tree_hash(src)
    return {"vcs": None, "tree_sha256": th, "file_count": len(listing), "entry": entry}


def entry_of(tc_name, params):
    """The entry file a build actually compiled: the toolchain's entry parameter, or None
    (every top-level .c) when the toolchain has none or it is empty."""
    ep = toolchain(tc_name)["entry_param"]
    return (params.get(ep) or None) if ep else None


def preset_matches(tc_name, preset, params):
    """True iff every platform twin's resolution of `preset` equals params, ignoring only
    the entry parameter (recorded as source.entry)."""
    ep = toolchain(tc_name)["entry_param"]
    for rname in toolchain(tc_name)["platforms"].values():
        try:
            base = buildmod.resolve_params(buildmod.load_recipe(rname), None, preset)
        except buildmod.BuildError:
            return False
        if {k: v for k, v in base.items() if k != ep} != {k: v for k, v in params.items() if k != ep}:
            return False
    return True


def preset_label(tc_name, preset, params):
    """A preset label is recorded only if it describes the params actually used."""
    return preset if preset is not None and preset_matches(tc_name, preset, params) else None


# ---------------- toolchain / builder block ----------------

def toolchain(name):
    if name not in TOOLCHAINS:
        raise HookcError("unknown toolchain %r (have: %s)" % (name, ", ".join(sorted(TOOLCHAINS))))
    return TOOLCHAINS[name]


def platform_pins(tc_name):
    out = {}
    for plat, rname in sorted(toolchain(tc_name)["platforms"].items()):
        r = buildmod.load_recipe(rname)
        if r["platform"] != plat:
            raise HookcError("recipe %s is %s, toolchain %s lists it as %s" % (rname, r["platform"], tc_name, plat))
        out[plat] = {"recipe": rname, "recipe_digest": buildmod.recipe_digest(r),
                     "base_image": r["base_image"],
                     "artifacts": [{"name": a["name"], "sha256": a["sha256"], "url": a["url"]}
                                   for a in r["artifacts"]]}
    return out


def _log_field(log, key):
    for line in log.splitlines():
        if line.startswith(key + ": "):
            return line[len(key) + 2:]
    return None


def _log_commands(log):
    lines, on = [], False
    for line in log.splitlines():
        if line.startswith("--- "):
            on = line == "--- commands"
            continue
        if on and line.strip():
            lines.append(line)
    return lines


WASM_OPT_LINES = ("HOOKC_WASM_OPT_RAN=0", "HOOKC_WASM_OPT_RAN=1")


def wasm_opt_ran(log):
    """builder.wasm_opt, ONLY from the pipeline's own `HOOKC_WASM_OPT_RAN=0|1` line in the
    build log header (before the first `--- ` section), which the pipeline sets after the
    wasm-opt stage actually exited 0. Never inferred from command lines: a source named
    wasm-opt.c appears in clang's. Missing, repeated or malformed -> refused."""
    vals = []
    for line in log.splitlines():
        if line.startswith("--- "):
            break
        if line.startswith("HOOKC_WASM_OPT_RAN"):
            vals.append(line)
    if len(vals) != 1 or vals[0] not in WASM_OPT_LINES:
        raise HookcError("build log does not state exactly once whether wasm-opt ran (HOOKC_WASM_OPT_RAN=0|1): %r"
                         % vals)
    return vals[0] == WASM_OPT_LINES[1]


def wce_pin():
    r = buildmod.load_recipe(WCE_RECIPE)
    return {"tool": "xahaud validateGuards (include/xrpl/hook/Guard.h), GUARD_CHECKER_BUILD",
            "xahaud_commit": WCE_XAHAUD_COMMIT,
            "recipe": WCE_RECIPE, "recipe_digest": buildmod.recipe_digest(r),
            "headers": {a["name"]: a["sha256"] for a in r["artifacts"]},
            "bound": "worst-case count of wasm instructions per validateGuards (guard-derived loop "
                     "multipliers; host-function internals not counted); SetHook stores the same "
                     "numbers as HookDefinition Fee / HookCallbackFee via computeExecutionFee"}


def run_wce(wasm, log=print):
    """Run xahaud's validateGuards on wasm in the pinned hookc-wce image.
    Returns ({"hook":N,"cbak":M} | None, reason | None); raises if the module is rejected."""
    try:
        recipe = buildmod.load_recipe(WCE_RECIPE)
        image = buildmod.ensure_image(recipe, log)
    except (buildmod.BuildError, OSError) as e:
        return None, "WCE tool unavailable: %s" % str(e)[:300]
    d = tempfile.mkdtemp(prefix="hookc-wce-", dir=_tmp_root())
    try:
        os.makedirs(os.path.join(d, "in"))
        os.makedirs(os.path.join(d, "out"))
        with open(os.path.join(d, "in", "hook.wasm"), "wb") as f:
            f.write(wasm)
        name = buildmod.container_name(recipe)
        try:
            r = buildmod.run_named(["docker", "run", "--rm", "--name", name, "--network", "none", "--read-only",
                                    "--platform", recipe["platform"],
                                    "-v", "%s:/src:ro" % os.path.join(d, "in"), "-v", "%s:/out" % os.path.join(d, "out"),
                                    image["image_id"], "/bin/sh", "/tc/" + recipe["pipeline"]], name, 300)
        except buildmod.BuildError as e:
            return None, "WCE tool did not finish: %s" % e
        if r.returncode != 0:
            return None, "WCE tool failed to run: %s" % (r.stderr or r.stdout)[-300:]
        with open(os.path.join(d, "out", "wce.rc")) as f:
            rc = f.read().strip()
        with open(os.path.join(d, "out", "wce.json")) as f:
            txt = f.read().strip()
        with open(os.path.join(d, "out", "wce.log")) as f:
            glog = f.read()
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return parse_wce_output(rc, txt, glog)


def parse_wce_output(rc, txt, glog=""):
    try:
        doc = json.loads(txt)
    except ValueError:
        return None, "WCE tool printed no JSON (rc %s)" % rc
    if rc == "0" and doc.get("valid") is True:
        h, c = doc.get("hook"), doc.get("cbak")
        if type(h) is not int or type(c) is not int or h < 0 or c < 0:
            return None, "WCE tool output malformed: %r" % txt[:200]
        return {"hook": h, "cbak": c}, None
    if rc == "1" and doc.get("valid") is False:
        raise HookcError("xahaud validateGuards REJECTS this module (SetHook would fail): %s"
                         % glog.strip()[-600:])
    return None, "WCE tool error (rc %s): %s" % (rc, glog.strip()[-300:])


def _tmp_root():
    d = os.path.join(buildmod.CACHE, "tmp")
    os.makedirs(d, exist_ok=True)
    return d


def exports_of(wasm):
    try:
        mod = wasm_parse(wasm)
    except WasmError as e:
        raise HookcError("built output is not a parseable wasm module: %s" % e)
    # structured (name, kind, index): an export NAME may contain ':' ("cbak:0", "evil:fn")
    funcs = sorted(name for name, kind, _ in mod["export_entries"] if kind == 0)
    if len(set(funcs)) != len(funcs):
        raise HookcError("built module exports a function name twice: %s" % funcs)
    imports = [i.rsplit(":", 1)[0] for i in mod["imports"]]
    return funcs, imports


# ---------------- metadata ----------------

def make_metadata(decls, wasm, wce, wce_reason, tc_name, preset, params, log_txt, src_block, built):
    """built: the platform twins this build actually built (twice each) and byte-compared;
    recorded as builder.platforms_built. builder.platforms lists every PINNED twin (so any
    twin can be reproduced), which is not a claim that it was built."""
    funcs, imports = exports_of(wasm)
    built = sorted(built)
    pins = platform_pins(tc_name)
    if not built or len(set(built)) != len(built) or not set(built) <= set(pins):
        raise HookcError("platforms_built %r is not a non-empty set of %s twins %s" % (built, tc_name, sorted(pins)))
    if "hook" not in funcs:
        raise HookcError("built module exports no `hook` function (exports: %s)" % funcs)
    extra = [f for f in funcs if f not in ("hook", "cbak")]
    if extra:
        raise HookcError("built module exports functions other than exactly `hook` and `cbak`: %r (xahaud calls "
                         "only exports named exactly hook/cbak)" % extra)
    if (wce is None) != (wce_reason == NO_WCE_REASON) or (wce is not None and wce_reason is not None):
        raise HookcError("WCE %r with reason %r: a sidecar has either validateGuards' numbers (reason null) or WCE "
                         "null with reason %r" % (wce, wce_reason, NO_WCE_REASON))
    on = hook_mask(decls["on"]) if decls["on_form"] == "list" else ("0" * 64 if decls["on_form"] == "all" else None)
    builder = {
        "name": BUILDER_NAME, "version": HOOKC_VERSION,
        "toolchain": tc_name, "preset": preset, "params": dict(sorted(params.items())),
        "cc": _log_field(log_txt, "clang_version"),
        "wasm_opt_version": _log_field(log_txt, "wasm_opt_version"),
        "commands": _log_commands(log_txt),
        "wasm_opt": wasm_opt_ran(log_txt),
        "env": dict(sorted(buildmod.FIXED_ENV.items())),
        "platforms": pins,
        "platforms_built": built,
        "wce": dict(wce_pin(), reason=wce_reason),
    }
    return {
        "index": decls["index"],
        "hook_fn": "hook",
        "cbak_fn": "cbak" if "cbak" in funcs else None,
        "name": "hook",
        "description": decls["description"],
        "HookOn": on,
        "HookCanEmit": hook_mask(decls["can_emit"]),
        "HookName": decls["name"].encode().hex().upper() if decls["name"] is not None else None,
        "HookHash": sha512half(wasm),
        "WCE": {"hook": wce["hook"] if wce else None, "cbak": wce["cbak"] if wce else None},
        "builder": builder,
        "human": {"on": {"form": decls["on_form"], "HookOn": decls["on"],
                         "HookOnIncoming": None, "HookOnOutgoing": None},
                  "HookCanEmit": decls["can_emit"], "HookName": decls["name"]},
        "chain": None,
        "source": src_block,
    }


def emit_warnings(meta, wasm):
    """rshooks-style can_emit/cbak cross-checks: warnings, never a build failure."""
    _, imports = exports_of(wasm)
    emits = "env.emit" in imports
    ce = meta["human"]["HookCanEmit"]
    w = []
    if emits and ce == []:
        w.append("module imports emit but can_emit = [] (deny-all)")
    if ce and not emits:
        w.append("can_emit declares %s but the module never imports emit" % ce)
    if meta["cbak_fn"] and not emits:
        w.append("module exports cbak but never imports emit")
    return w


def dumps(meta):
    """rshooks sidecar formatting: 2-space pretty JSON, insertion key order, trailing newline."""
    return json.dumps(meta, indent=2, ensure_ascii=False) + "\n"


def parse_metadata(doc):
    """Strict parse of a hookc sidecar; returns the fields reproduce/verify use.
    Refuses anything without source provenance."""
    if not isinstance(doc, dict):
        raise HookcError("metadata is not an object")
    b = doc.get("builder")
    if not isinstance(b, dict) or b.get("name") != BUILDER_NAME:
        raise HookcError("builder.name is not hookc")
    if b.get("version") != HOOKC_VERSION:
        raise HookcError("metadata written by hookc %r; this is hookc %s" % (b.get("version"), HOOKC_VERSION))
    idx = doc.get("index")
    if type(idx) is not int or not 0 <= idx <= MAX_INDEX:
        raise HookcError("index %r out of range" % idx)
    if doc.get("hook_fn") != "hook":
        raise HookcError("hook_fn must be hook for a C hook")
    hh = doc.get("HookHash")
    if not isinstance(hh, str) or not HASH_RE.match(hh):
        raise HookcError("HookHash %r is not 64 uppercase hex" % hh)
    for k in ("HookOn", "HookCanEmit"):
        if doc.get(k) is not None and not MASK_RE.match(str(doc[k])):
            raise HookcError("%s %r is not a 64-hex mask" % (k, doc[k]))
    tc = b.get("toolchain")
    toolchain(tc)
    params = b.get("params")
    if not isinstance(params, dict) or not all(isinstance(v, str) for v in params.values()):
        raise HookcError("builder.params must map names to strings")
    plats = b.get("platforms")
    if (not isinstance(plats, dict) or set(plats) != set(toolchain(tc)["platforms"])
            or not all(isinstance(v, dict) for v in plats.values())):
        raise HookcError("builder.platforms must map exactly the toolchain's twins %s to pin objects"
                         % sorted(toolchain(tc)["platforms"]))
    built = b.get("platforms_built")
    if (not isinstance(built, list) or not built or built != sorted(set(built))
            or not set(built) <= set(toolchain(str(tc))["platforms"])):
        raise HookcError("builder.platforms_built %r is not a sorted, non-empty list of the toolchain's twins" % (built,))
    src = doc.get("source")
    if not isinstance(src, dict):
        raise HookcError("metadata has no source provenance block; refusing")
    vcs = src.get("vcs")
    if not isinstance(vcs, dict) or vcs.get("type") != "git":
        raise HookcError("metadata has no git provenance (source.vcs); refusing")
    if not GIT_RE.match(str(vcs.get("commit"))) or not GIT_RE.match(str(vcs.get("tree"))):
        raise HookcError("source.vcs commit/tree are not 40-hex git ids")
    if vcs.get("dirty") is not False:
        raise HookcError("source.vcs is dirty; refusing")
    check_vcs_path(str(vcs.get("path", "")))  # clean relative path, no .git / ignore-dir component
    if not SHA_RE.match(str(src.get("tree_sha256"))):
        raise HookcError("source.tree_sha256 missing or malformed; refusing")
    wce, wb = doc.get("WCE"), b.get("wce")
    if not isinstance(wce, dict) or set(wce) != {"hook", "cbak"} or not isinstance(wb, dict):
        raise HookcError("metadata WCE / builder.wce block is missing or malformed")
    nums = [v for v in (wce["hook"], wce["cbak"]) if type(v) is int and v >= 0]
    if not ((len(nums) == 2 and wb.get("reason") is None)
            or (wce["hook"] is None and wce["cbak"] is None and wb.get("reason") == NO_WCE_REASON)):
        raise HookcError("metadata WCE %r with builder.wce.reason %r: expected validateGuards' two numbers with reason "
                         "null, or null WCE with reason %r" % (wce, wb.get("reason"), NO_WCE_REASON))
    entry = src.get("entry")
    if entry is not None and not ENTRY_RE.match(str(entry)):
        raise HookcError("source.entry %r is not a .c file name" % entry)
    for rname in toolchain(tc)["platforms"].values():
        try:
            full = buildmod.resolve_params(buildmod.load_recipe(rname), params, None)
        except buildmod.BuildError as e:
            raise HookcError("builder.params %s are not valid for recipe %s: %s" % (params, rname, e))
        if full != params:
            raise HookcError("builder.params %s are not the fully resolved params %s" % (params, full))
    if entry != entry_of(tc, params):
        raise HookcError("source.entry %r is not the entry the params compile (%r)" % (entry, entry_of(tc, params)))
    preset = b.get("preset")
    if preset is not None and not preset_matches(tc, preset, params):
        raise HookcError("builder.preset %r does not resolve to builder.params %s; refusing the label" % (preset, params))
    return {"hookhash": hh, "index": idx, "toolchain": tc, "preset": preset,
            "params": dict(params), "platforms": plats, "platforms_built": list(built), "source": src, "doc": doc,
            "entry": "%d.hook" % idx}


def load_metadata_file(path):
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        raise HookcError("cannot read metadata %s: %s" % (path, e))
    try:
        text = raw.decode("utf-8")
        doc = json.loads(text)
    except ValueError as e:
        raise HookcError("metadata is not UTF-8 JSON: %s" % e)
    meta = parse_metadata(doc)
    meta["text"] = text
    return meta


def native_platform():
    m = _platform.machine().lower()
    return {"arm64": "linux/arm64", "aarch64": "linux/arm64", "x86_64": "linux/amd64", "amd64": "linux/amd64"}.get(m)


def select_platform(meta, platform=None):
    """Pick the recipe for `platform` (default: first listed); the local recipe must still
    have the digest the metadata recorded (no silent toolchain drift)."""
    plats = meta["platforms"]
    plat = platform or (native_platform() if native_platform() in plats else sorted(plats)[0])
    if plat not in plats:
        raise HookcError("metadata lists no %s twin (has: %s)" % (plat, ", ".join(sorted(plats))))
    pin = plats[plat]
    want = toolchain(meta["toolchain"])["platforms"].get(plat)
    if pin.get("recipe") != want:
        raise HookcError("metadata %s recipe %r is not toolchain %s's %r" % (plat, pin.get("recipe"), meta["toolchain"], want))
    have = buildmod.recipe_digest(buildmod.load_recipe(want))
    if pin.get("recipe_digest") != have:
        raise HookcError("toolchain drift: metadata pins %s digest %s, local recipe is %s"
                         % (want, pin.get("recipe_digest"), have))
    return plat, want


def check_index_flags(repo, path):
    """Refuse (exit 3) any index entry under <path> flagged skip-worktree or assume-unchanged
    (`git ls-files -v`: 'S' or a lowercase tag): with those flags `git status` stays clean
    while the work tree holds other bytes. Only 'H' (plain cached) entries are accepted."""
    out = _git(repo, "ls-files", "-v", "-z", "--", path or ".", binary=True)
    bad = []
    for ent in out.split(b"\0"):
        if not ent:
            continue
        tag, name = ent[:1], ent[2:]
        if tag != b"H":
            bad.append("%s %s" % (tag.decode("ascii", "replace"), name.decode("utf-8", "replace")))
    if bad:
        raise HookcError("--src work tree: index entries under %s are flagged skip-worktree/assume-unchanged or "
                         "unmerged (git status would not show edits to them); refusing. Clear the flags "
                         "(`git update-index --no-skip-worktree --no-assume-unchanged <file>`) or use --git. "
                         "Found: %s" % (path or ".", "; ".join(bad[:8])))


def worktree_files(top, path):
    """Every file in the work tree under top/<path> as sorted [(relpath, sha256 of the on-disk
    bytes)]. Only `.git` directly in the repository toplevel is skipped (and only when <path>
    is the toplevel); symlinks (also as a component of <path>) and non-regular files are
    refused. Nothing else is skipped: ignored, untracked and ignore-dir files are listed."""
    root, comps = top, [c for c in (path or "").split("/") if c]
    for c in comps:
        root = os.path.join(root, c)
        if os.path.islink(root) or not os.path.isdir(root):
            raise HookcError("--src work tree: %s is not a plain directory" % root)
    out = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        if dirpath == root and not comps:
            dirnames[:] = [d for d in dirnames if d != ".git"]
            filenames = [f for f in filenames if f != ".git"]  # a linked work tree's .git file
        for n in dirnames + filenames:
            full = os.path.join(dirpath, n)
            if os.path.islink(full):
                raise HookcError("--src work tree has a symlink %s; refusing" % full)
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            if not stat.S_ISREG(os.lstat(full).st_mode):
                raise HookcError("--src work tree has a non-regular file %s; refusing" % full)
            with open(full, "rb") as f:
                out.append((os.path.relpath(full, root).replace(os.sep, "/"), hashlib.sha256(f.read()).hexdigest()))
    out.sort(key=lambda e: e[0].encode("utf-8"))
    return out


def check_worktree_matches(top, path, listing):
    """RT4 F2: the --src work tree is what a reviewer reads, so its files under <path> must be
    exactly the exported blobs, byte for byte: same names, same sha256, no extra file (also
    none that is untracked or ignored). `git status` is not trusted for this (index flags hide
    edits); the on-disk bytes are hashed and compared to the blobs being built."""
    have = dict(worktree_files(top, path))
    want = dict(listing)
    diff = sorted(set(have) ^ set(want)) + sorted(n for n in set(have) & set(want) if have[n] != want[n])
    if diff:
        raise HookcError("--src work tree differs from the committed tree HEAD:%s that is built (%d files: %s); "
                         "a reviewer reading this work tree would read other text. Refusing; restore it "
                         "(`git status --ignored`, `git ls-files -v`) or use --git"
                         % (path or ".", len(diff), ", ".join(diff[:8])))


def export_for_metadata(meta, src=None, git=None):
    """Export the sidecar's own <commit>:<path> from a repository: `git` (any clone holding
    the commit) or `src` (a git work tree whose HEAD:<path> is the sidecar's tree). The
    build uses only the export; with `src`, the work tree's files under <path> must also be
    byte-identical to the exported blobs (no extra file, no skip-worktree/assume-unchanged
    entry), else refused. Returns (export_dir, info, cleanup_dir)."""
    if bool(src) == bool(git):
        raise HookcError("give exactly one of a git repository or a git work tree")
    vcs = meta["source"]["vcs"]
    if src:
        loc, why = worktree_location(src)
        if loc is None:
            raise HookcError("--src %s: %s; a hookc sidecar is rebuilt only from git objects" % (src, why))
        repo = loc[0]
        if loc[1] not in ("", vcs["path"]):
            raise HookcError("--src %s is %s in its repository; the sidecar's source is %s "
                             "(give the repository root or that directory)"
                             % (src, loc[1], vcs["path"] or "."))
        fmt = git_repo_check(repo)
        head_tree = resolve_tree(repo, resolve_commit(repo, "HEAD", fmt)[1], vcs["path"], fmt)
        if head_tree != vcs["tree"]:
            raise HookcError("--src work tree HEAD:%s is tree %s, the sidecar names %s"
                             % (vcs["path"] or ".", head_tree, vcs["tree"]))
        check_index_flags(repo, vcs["path"])
    else:
        repo = git
    d = tempfile.mkdtemp(prefix="hookc-src-", dir=_tmp_root())
    try:
        info = export_tree(repo, vcs["commit"], vcs["path"], os.path.join(d, "src"))
        if info["vcs"]["commit"] != vcs["commit"] or info["vcs"]["tree"] != vcs["tree"]:
            raise HookcError("git commit/tree %s/%s != sidecar %s/%s" % (
                info["vcs"]["commit"], info["vcs"]["tree"], vcs["commit"], vcs["tree"]))
        if src:
            check_worktree_matches(repo, vcs["path"], info["listing"])
    except BaseException:
        shutil.rmtree(d, ignore_errors=True)
        raise
    return os.path.join(d, "src"), info, d


def params_for(tc_name, entry, params):
    p = dict(params or {})
    ep = toolchain(tc_name)["entry_param"]
    if entry:
        if not ENTRY_RE.match(entry):
            raise HookcError("entry %r is not a .c file name" % entry)
        if not ep:
            raise HookcError("toolchain %s compiles every top-level .c; it has no entry selector" % tc_name)
        p[ep] = entry
    return p


# ---------------- build / reproduce ----------------

def _double_build(src, recipe, params, preset, out_dir, log, tree_sha256=None):
    got = []
    for n in (1, 2):
        m, wasm = buildmod.build(src, recipe, params, preset, os.path.join(out_dir, "build%d" % n), log=log)
        got.append((m, wasm))
    (m1, w1), (m2, w2) = got
    if w1 != w2:
        raise HookcError("NOT DETERMINISTIC: %s build1 %s != build2 %s\n%s" % (
            recipe, sha512half(w1), sha512half(w2), json.dumps(wasm_diff(w1, w2, "build1", "build2"))[:2000]))
    if m1["image"]["image_id"] != m2["image"]["image_id"]:
        raise HookcError("build1 and build2 ran different images (%s, %s)" % (m1["image"]["image_id"], m2["image"]["image_id"]))
    for m in (m1, m2):
        if tree_sha256 is not None and m["source"]["tree_sha256"] != tree_sha256:
            raise HookcError("the container received tree %s, not the exported tree %s"
                             % (m["source"]["tree_sha256"], tree_sha256))
    return m1, w1


def materialize(src=None, git=None, rev=None, path="", allow_unversioned=False):
    """Returns (src_dir, info|None, cleanup_dir|None). A versioned source (--git, or a clean
    git work tree) is ALWAYS the export of its commit; only --allow-unversioned builds a
    directory as it is (and such metadata has no provenance)."""
    if git:
        repo, rev, path = git, rev or "HEAD", path or ""
    else:
        vcs, why = vcs_of_dir(src)
        if vcs is None:
            if not allow_unversioned:
                raise HookcError("no source provenance: %s. Commit it and use --git/--rev, or pass "
                                 "--allow-unversioned (such metadata cannot be reproduced or verified)" % why)
            return src, None, None
        repo, rev, path = worktree_location(src)[0][0], vcs["commit"], vcs["path"]
    d = tempfile.mkdtemp(prefix="hookc-src-", dir=_tmp_root())
    try:
        info = export_tree(repo, rev, path, os.path.join(d, "src"))
    except BaseException:
        shutil.rmtree(d, ignore_errors=True)
        raise
    return os.path.join(d, "src"), info, d


def build(src=None, git=None, rev=None, path="", tc_name="kvt-llvm22", preset=None, params=None,
          entry=None, platforms=None, decls=None, decl_warnings=(), out_dir=".", with_wce=True,
          allow_unversioned=False, log=print):
    tc = toolchain(tc_name)
    preset = preset or tc["default_preset"]
    plats = platforms or sorted(tc["platforms"])
    for p in plats:
        if p not in tc["platforms"]:
            raise HookcError("toolchain %s has no %s twin. %s" % (tc_name, p, tc["note"]))
    decls = decls or normalize_decls({})[0]
    p = params_for(tc_name, entry, params)
    src_dir, info, cleanup = materialize(src, git, rev, path, allow_unversioned)
    try:
        want_tree = info["tree_sha256"] if info else tree_hash(src_dir)[0]
        results = {}
        for plat in plats:
            rname = tc["platforms"][plat]
            m, wasm = _double_build(src_dir, rname, p, preset, os.path.join(out_dir, "builds", plat.replace("/", "-")),
                                    log, tree_sha256=want_tree)
            results[plat] = (m, wasm)
        first = plats[0]
        w0 = results[first][1]
        for plat in plats[1:]:
            if results[plat][1] != w0:
                raise HookcError("CROSS-PLATFORM MISMATCH: %s %s != %s %s\n%s" % (
                    first, sha512half(w0), plat, sha512half(results[plat][1]),
                    json.dumps(wasm_diff(w0, results[plat][1], first, plat))[:2000]))
        m0 = results[first][0]
        resolved = m0["params"]
        sb = source_block(src_dir, info, entry_of(tc_name, resolved))
        if with_wce:
            wce, why = run_wce(w0, log)
            if wce is None:
                raise HookcError("WCE tool could not run: %s. No sidecar written: a sidecar never carries a "
                                 "host-specific failure. Fix the hookc-wce image or pass --no-wce (WCE null, "
                                 "reason %r)" % (why, NO_WCE_REASON))
        else:
            wce, why = None, NO_WCE_REASON
        meta = make_metadata(decls, w0, wce, why, tc_name, preset_label(tc_name, preset, resolved), resolved,
                             m0["container_log"], sb, list(results))
        stem = "%d.hook" % decls["index"]
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, stem + ".wasm"), "wb") as f:
            f.write(w0)
        with open(os.path.join(out_dir, stem + ".metadata.json"), "w") as f:
            f.write(dumps(meta))
        summary = {"stem": stem, "HookHash": meta["HookHash"], "size": len(w0), "sha256": sha256_hex(w0),
                   "platforms": {pl: {"recipe": results[pl][0]["recipe"]["name"],
                                      "recipe_digest": results[pl][0]["recipe"]["digest"],
                                      "image_id": results[pl][0]["image"]["image_id"],
                                      "builds_identical": True} for pl in plats},
                   "WCE": meta["WCE"], "wce_reason": why,
                   "warnings": list(decl_warnings) + emit_warnings(meta, w0),
                   "source": sb}
        return meta, w0, summary
    finally:
        if cleanup:
            shutil.rmtree(cleanup, ignore_errors=True)


def metadata_diff(a, b, prefix=""):
    """Paths where two metadata documents differ."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for k in list(a) + [k for k in b if k not in a]:
            out += metadata_diff(a.get(k, "<absent>"), b.get(k, "<absent>"), prefix + "." + k if prefix else k)
        return out
    return [] if a == b and type(a) is type(b) else [prefix or "<root>"]


def decls_from_human(d):
    """Re-derive declarations from the sidecar's readable `human` block, validated exactly as
    a build's declarations are (the regenerated masks must then equal the top-level ones)."""
    h = d.get("human")
    on = h.get("on") if isinstance(h, dict) else None
    if not isinstance(on, dict) or on.get("form") not in ("omitted", "all", "list"):
        raise HookcError("metadata human.on block is missing or malformed")
    if on["form"] == "list" and on.get("HookOn") is None:
        raise HookcError("metadata human.on form=list without a HookOn list")
    raw = {"index": d.get("index"), "name": h.get("HookName"), "description": d.get("description"),
           "on": "all" if on["form"] == "all" else on.get("HookOn"), "can_emit": h.get("HookCanEmit")}
    return normalize_decls(raw)[0]


def regenerate(meta, wasm, manifest, info, with_wce=True, log=print, built=None):
    """The sidecar this build actually justifies: every field recomputed from the rebuilt
    bytes, the build manifest and the git export; nothing is copied from the given sidecar
    except the declarations, which are re-validated from its readable `human` block, and
    (only when `built` is None, i.e. a single-twin rebuild) builder.platforms_built, which is
    then the original build's record and is reported as not re-checked."""
    if manifest["source"]["tree_sha256"] != info["tree_sha256"]:
        raise HookcError("the container received tree %s, not the exported tree %s"
                         % (manifest["source"]["tree_sha256"], info["tree_sha256"]))
    tc = meta["toolchain"]
    params = manifest["params"]
    decls = decls_from_human(meta["doc"])
    wce, why = regen_wce(meta["doc"], wasm, with_wce, log)
    sb = source_block(None, info, entry_of(tc, params))
    return make_metadata(decls, wasm, wce, why, tc, preset_label(tc, meta["preset"], params), params,
                         manifest["container_log"], sb, meta["platforms_built"] if built is None else built)


def regen_wce(doc, wasm, with_wce=True, log=print):
    """(wce, reason) for the regenerated sidecar. A --no-wce sidecar (WCE null) states no WCE:
    it regenerates as null with NO_WCE_REASON. A sidecar that states validateGuards' numbers
    needs the pinned tool to run here; if it cannot (--no-wce, image unusable, tool error) the
    claim is unchecked -> WceUnavailable (UNVERIFIED), never a regenerated null (MISMATCH)."""
    if (doc.get("WCE") or {}).get("hook") is None:
        return None, NO_WCE_REASON
    if not with_wce:
        raise WceUnavailable("the sidecar states WCE %s but this run has --no-wce, so it was not recomputed"
                             % json.dumps(doc["WCE"], sort_keys=True))
    wce, why = run_wce(wasm, log)
    if wce is None:
        raise WceUnavailable("the sidecar's WCE could not be recomputed: %s" % why)
    return wce, None


def sidecar_check(meta, wasm, manifest, info, with_wce=True, log=print, built=None):
    """(ok, reason, diff): the regenerated sidecar must be byte-identical to the given one."""
    regen = regenerate(meta, wasm, manifest, info, with_wce, log, built)
    diff = metadata_diff(meta["doc"], regen)
    if diff or dumps(regen) != meta["text"]:
        return False, "sidecar differs from the one this build regenerates at: %s" % (", ".join(diff) or "formatting"), diff
    return True, None, []


def reproduce(metadata_path, src=None, git=None, platform=None, ref_wasm=None, out_dir=None,
              with_wce=True, log=print):
    """Rebuild from metadata. Without `platform`, every twin the sidecar says was built
    (builder.platforms_built) is rebuilt twice and they must all agree, so that claim is
    re-checked; with `platform`, only that twin is rebuilt and platforms_built is reported as
    the original build's record, not re-checked. Verdict REPRODUCED iff the rebuilds of the
    git export of the sidecar's commit/path are identical, their SHA512Half is the metadata
    HookHash, the sidecar regenerated from them is byte-identical to the given one, and (if
    given) the reference wasm is those same bytes."""
    meta = load_metadata_file(metadata_path)
    rep = {"schema": "hookc/reproduce-report/v1", "metadata": os.path.basename(metadata_path),
           "HookHash": meta["hookhash"], "verdict": "UNVERIFIED", "reason": None,
           "platform": None, "platforms_rebuilt": [], "platforms_built_claim": meta["platforms_built"],
           "platforms_built_rechecked": False, "rebuilt": None, "metadata_diff": [], "diff": None}
    ref = None
    if ref_wasm:
        try:
            with open(ref_wasm, "rb") as f:
                ref = f.read()
        except OSError as e:
            rep["reason"] = "cannot read reference wasm %s: %s" % (ref_wasm, e.strerror or e)
            return rep
        if sha512half(ref) != meta["hookhash"]:
            rep["reason"] = "reference wasm HookHash %s is not the metadata HookHash" % sha512half(ref)
            rep["diff"] = None
            return rep
    twins = [select_platform(meta, p) for p in ([platform] if platform else meta["platforms_built"])]
    rep["platform"] = twins[0][0]
    src_dir, info, cleanup = export_for_metadata(meta, src=src, git=git)
    tmp_out = None
    try:
        if not out_dir:
            out_dir = tmp_out = tempfile.mkdtemp(prefix="hookc-repro-", dir=_tmp_root())
        got = []
        for plat, recipe in twins:
            m, wasm = _double_build(src_dir, recipe, meta["params"], meta["preset"],
                                    os.path.join(out_dir, plat.replace("/", "-")), log, tree_sha256=info["tree_sha256"])
            got.append((plat, recipe, m, wasm))
            rep["platforms_rebuilt"].append(plat)
        plat, recipe, m, wasm = got[0]
        rep["rebuilt"] = {"HookHash": sha512half(wasm), "size": len(wasm), "recipe": recipe,
                          "recipe_digest": m["recipe"]["digest"], "image_id": m["image"]["image_id"],
                          "source": {"commit": info["vcs"]["commit"], "tree": info["vcs"]["tree"],
                                     "tree_sha256": info["tree_sha256"]}}
        for p2, _, _, w2 in got:
            if sha512half(w2) != meta["hookhash"]:
                rep["verdict"] = "MISMATCH"
                rep["reason"] = "rebuilt HookHash %s (%s) != metadata HookHash %s" % (sha512half(w2), p2, meta["hookhash"])
                if ref is not None:
                    rep["diff"] = wasm_diff(ref, w2, "reference", "rebuilt")
                return rep
        built = None if platform else [p for p, _, _, _ in got]
        try:
            ok, why, rep["metadata_diff"] = sidecar_check(meta, wasm, m, info, with_wce, log, built)
        except WceUnavailable as e:  # a tool that did not run compared nothing: UNVERIFIED
            rep["reason"] = "bytes reproduce (HookHash %s) but %s; WCE NOT checked" % (meta["hookhash"], e)
            return rep
        if not ok:
            rep["verdict"] = "MISMATCH"
            rep["reason"] = "bytes reproduce but " + why
            return rep
        rep["platforms_built_rechecked"] = built is not None
        rep["verdict"] = "REPRODUCED"
        rep["reason"] = ("two clean rebuilds on each of %s of git %s:%s are byte-identical, HookHash %s, sidecar "
                         "regenerated byte-identical; " % ("+".join(rep["platforms_rebuilt"]), info["vcs"]["commit"][:12],
                                                           info["vcs"]["path"] or ".", meta["hookhash"]))
        rep["reason"] += ("builder.platforms_built %s re-checked" % "+".join(meta["platforms_built"]) if built is not None
                          else "builder.platforms_built %s is the original build's record, NOT re-checked by this "
                               "single-twin run" % "+".join(meta["platforms_built"]))
        return rep
    finally:
        shutil.rmtree(cleanup, ignore_errors=True)
        if tmp_out:
            shutil.rmtree(tmp_out, ignore_errors=True)

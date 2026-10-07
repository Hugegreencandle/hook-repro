"""hook-repro CLI. Exit codes: 0 pass/REPRODUCED, 1 usage/internal error,
2 MISMATCH, 3 UNVERIFIED (or a binding that fails coverage)."""
import argparse
import json
import os
import shutil
import subprocess
import sys

from . import build as buildmod
from . import hookc
from . import rshooks_meta
from .bind import bind_review
from .fetch import fetch_createcode
from .hashing import sha512half
from .verify import EXIT, verify
from .wasm import diff as wasm_diff, render_diff


def _params(pairs):
    out = {}
    for p in pairs or []:
        if "=" not in p:
            raise SystemExit("--param expects KEY=VALUE, got %r" % p)
        k, v = p.split("=", 1)
        out[k] = v
    return out


def refuse_out_in_source(out, *roots):
    """--out must not lie inside (or be) a source dir or repository given on the command line:
    outputs written there would be part of what a later build or review reads."""
    r = buildmod.out_inside(out, *roots) if out else None
    if r:
        raise buildmod.BuildError("--out %s lies inside the source %s; build outputs are never written into the tree "
                                  "being built or reviewed. Choose an --out outside it" % (out, r))


def _builder_name(path):
    try:
        with open(path) as f:
            b = json.load(f).get("builder")
    except (ValueError, AttributeError):
        return None
    return b.get("name") if isinstance(b, dict) else None


def resolve_recipe(recipe, params, metadata_path, platform=None):
    """--metadata (an rshooks or hookc sidecar) selects the recipe and entry; explicit flags
    must agree. A hookc sidecar's source is always the git export of its own commit/path
    (see hookc.export_for_metadata), never a directory as given."""
    meta = None
    if metadata_path and _builder_name(metadata_path) == hookc.BUILDER_NAME:
        # hookc (C) sidecar: toolchain twin + preset + params come from the metadata
        meta = hookc.load_metadata_file(metadata_path)
        plat, want = hookc.select_platform(meta, platform)
        if recipe and recipe != want:
            raise hookc.HookcError("metadata selects recipe %s; --recipe %s contradicts it" % (want, recipe))
        if params and params != meta["params"]:
            raise hookc.HookcError("--param contradicts the metadata's recorded params %s" % meta["params"])
        return want, dict(meta["params"]), meta
    if metadata_path:
        meta = rshooks_meta.load_metadata(metadata_path)
        recipe, mp = rshooks_meta.select_recipe(meta, recipe)
        if params.get("ENTRY", mp["ENTRY"]) != mp["ENTRY"]:
            raise rshooks_meta.MetadataError("--param ENTRY=%s contradicts metadata entry %s"
                                             % (params["ENTRY"], mp["ENTRY"]))
        params = dict(params, **mp)
    return recipe or "xhc-bin127", params, meta


def cmd_recipes(a):
    for n in buildmod.list_recipes():
        r = buildmod.load_recipe(n)
        print("%-12s %s\n             digest %s  presets: %s" % (
            n, r["platform"], buildmod.recipe_digest(r), ", ".join(r.get("presets", {}))))
    return 0


def cmd_build(a):
    if a.metadata and _builder_name(a.metadata) == hookc.BUILDER_NAME:
        raise hookc.HookcError("a hookc sidecar is rebuilt with `hookc reproduce --metadata M --git REPO`, "
                               "which builds the git export of its commit, not a directory")
    recipe, params, meta = resolve_recipe(a.recipe, _params(a.param), a.metadata, None)
    refuse_out_in_source(a.out, a.src)
    if not buildmod.docker_available():
        print("UNVERIFIED: docker daemon not reachable (`docker info` failed)", file=sys.stderr)
        return 3
    m, wasm = buildmod.build(a.src, recipe, params, a.preset, a.out, log=lambda s: print(s, file=sys.stderr))
    print(json.dumps({k: m[k] for k in ("recipe", "params", "output")} |
                     {"source_tree_sha256": m["source"]["tree_sha256"],
                      "image_id": m["image"]["image_id"],
                      "manifest": os.path.join(os.path.dirname(m["output"]["file"]), "build-manifest.json")},
                     indent=2))
    return 0


def _render_verify(rep):
    print("VERDICT: %s" % rep["verdict"])
    print("reason:  %s" % rep["reason"])
    print("hookhash %s  network %s  recipe %s preset %s params %s" % (
        rep["hookhash"], rep["network"], rep["recipe"], rep["preset"], rep["params"]))
    for r in rep["reads"]:
        print("  read %-34s node %s.. ledger %s %s.. size %d sha512half %s" % (
            r["url"], (r["node_key"] or "")[:12], r["ledger_index"], (r.get("ledger_hash") or "")[:16],
            r["size"], r["sha512half"][:16]))
    for b in rep["builds"]:
        print("  build%d %ssize %d sha512half %s recipe %s src %s" % (
            b["n"], ("%s " % b["platform"]) if b.get("platform") else "", b["size"], b["sha512half"][:16],
            (b["recipe_digest"] or "")[:16], (b["source_tree_sha256"] or "")[:16]))
    if "platforms_built_rechecked" in rep:
        print("platforms_built_rechecked: %s (rebuilt: %s)" % (
            str(rep["platforms_built_rechecked"]).lower(), "+".join(rep["platforms_rebuilt"])))
    if rep.get("caveat"):
        print("CAVEAT: " + rep["caveat"])
    for r in (rep.get("definition_check") or {}).get("fields", []):
        print("  definition %-15s metadata %-11s %-5s %-13s %s vs %s" % (
            r["definition"], r["metadata"], {True: "match", False: "DIFF", None: "n/a"}[r["match"]],
            "(enforced)" if r["enforced"] else "(informative)", r["definition_value"], r["metadata_value"]))
    if rep.get("diff"):
        print(render_diff(rep["diff"]))


def cmd_verify(a):
    recipe, params, meta = resolve_recipe(a.recipe, _params(a.param), a.metadata,
                                          getattr(a, "platform", None))
    is_hookc = meta is not None and meta.get("doc") is not None
    if is_hookc:
        if a.preset and a.preset != meta["preset"]:
            raise hookc.HookcError("--preset %s contradicts metadata preset %s" % (a.preset, meta["preset"]))
        a.preset = meta["preset"]
        if bool(a.src) == bool(a.git):
            raise SystemExit("verify --metadata <hookc sidecar>: give exactly one of --src WORKTREE or --git REPO")
    elif a.git or not a.src:
        raise SystemExit("verify: --src DIR is required (--git only with a hookc sidecar)")
    refuse_out_in_source(a.out, a.src, a.git)
    if not buildmod.docker_available():
        rep = {"verdict": "UNVERIFIED", "reason": "docker daemon not reachable"}
        print(json.dumps(rep) if a.json else "VERDICT: UNVERIFIED\nreason:  docker daemon not reachable")
        return 3
    if is_hookc:
        # every twin the sidecar says was built is rebuilt (twice each) unless --platform restricts
        # it, in which case the report says builder.platforms_built was NOT re-checked
        plat = getattr(a, "platform", None)
        twins = [hookc.select_platform(meta, p) for p in ([plat] if plat else meta["platforms_built"])]
        src_dir, info, cleanup = hookc.export_for_metadata(meta, src=a.src, git=a.git)
        log = lambda s: print(s, file=sys.stderr)  # noqa: E731
        try:
            rep = verify(a.hookhash, src_dir, twins[0][1], a.network, params, a.preset, a.out,
                         allow_single_operator=a.allow_single_operator, metadata=meta,
                         sidecar=lambda wasm, m, built: hookc.sidecar_check(meta, wasm, m, info, log=log, built=built),
                         twins=twins, recheck_platforms_built=not plat, source_vcs=info["vcs"])
        finally:
            shutil.rmtree(cleanup, ignore_errors=True)
    else:
        if buildmod.preset_note(recipe, a.preset):
            print("NOTE: preset %s of %s %s" % (a.preset, recipe, buildmod.preset_note(recipe, a.preset)),
                  file=sys.stderr)
        rep = verify(a.hookhash, a.src, recipe, a.network, params, a.preset, a.out,
                     allow_single_operator=a.allow_single_operator, metadata=meta)
    if a.json:
        print(json.dumps(rep, indent=2, sort_keys=True))
    else:
        _render_verify(rep)
        if a.out:
            print("report: %s" % os.path.join(a.out, "verify-report.json"))
    return EXIT[rep["verdict"]]


def cmd_fetch(a):
    f = fetch_createcode(a.hookhash, a.network, allow_single_operator=a.allow_single_operator)
    for r in f["reads"]:
        print("read %s node %s ledger %s size %d" % (r["url"], r["node_key"][:12], r["ledger_index"], len(r["code"])))
    if not f["ok"]:
        print("UNVERIFIED: %s" % f["reason"])
        return 3
    if a.out:
        with open(a.out, "wb") as fh:
            fh.write(f["code"])
    print("OK %d bytes, SHA512Half %s%s" % (len(f["code"]), sha512half(f["code"]), (" -> " + a.out) if a.out else ""))
    return 0


def cmd_diff(a):
    with open(a.a, "rb") as fa, open(a.b, "rb") as fb:
        d = wasm_diff(fa.read(), fb.read(), "a", "b")
    print(json.dumps(d, indent=2) if a.json else render_diff(d))
    return 0 if d["identical"] else 2


def cmd_bind(a):
    m, ok = bind_review(a.review, a.hookhash, a.network, a.verify_report)
    if not ok and not a.force:
        print("NOT BOUND: %s" % "; ".join(m["problems"]), file=sys.stderr)
        print(json.dumps(m, indent=2, sort_keys=True))
        return 3
    txt = json.dumps(m, indent=2, sort_keys=True)
    if a.out:
        with open(a.out, "w") as fh:
            fh.write(txt + "\n")
    print(txt)
    return 0


def _hookc_decls(a):
    ov = {"index": a.index, "name": a.hook_name, "description": a.description,
          "on": hookc.parse_tx_arg(a.on), "can_emit": hookc.parse_tx_arg(a.can_emit)}
    if ov["can_emit"] == "all":
        raise hookc.HookcError("--can-emit all is not a thing; omit it for no override")
    return hookc.load_decls(a.decl, ov)


def cmd_hookc_build(a):
    if not a.src and not a.git:
        raise SystemExit("hookc build: give a source dir or --git REPO [--rev R] [--path P]")
    decls, warns = _hookc_decls(a)
    refuse_out_in_source(a.out, a.src, a.git)
    if not buildmod.docker_available():
        print("UNVERIFIED: docker daemon not reachable (`docker info` failed)", file=sys.stderr)
        return 3
    plats = None if a.platform == ["all"] or not a.platform else a.platform
    meta, wasm, summary = hookc.build(
        src=a.src, git=a.git, rev=a.rev, path=a.path or "", tc_name=a.toolchain, preset=a.preset,
        params=_params(a.param), entry=a.entry, platforms=plats, decls=decls, decl_warnings=warns,
        out_dir=a.out, with_wce=not a.no_wce, allow_unversioned=a.allow_unversioned,
        log=lambda s: print(s, file=sys.stderr), select=a.select)
    for w in summary["warnings"]:
        print("warning: " + w, file=sys.stderr)
    print(json.dumps(summary, indent=2))
    return 0


def cmd_hookc_reproduce(a):
    if bool(a.src) == bool(a.git):
        raise SystemExit("hookc reproduce: give exactly one of --src DIR or --git REPO")
    refuse_out_in_source(a.out, a.src, a.git)
    if not buildmod.docker_available():
        print("VERDICT: UNVERIFIED\nreason:  docker daemon not reachable")
        return 3
    rep = hookc.reproduce(a.metadata, src=a.src, git=a.git, platform=a.platform, ref_wasm=a.wasm,
                          out_dir=a.out, with_wce=not a.no_wce, log=lambda s: print(s, file=sys.stderr))
    if a.json:
        print(json.dumps(rep, indent=2, sort_keys=True))
    else:
        print("VERDICT: %s" % rep["verdict"])
        print("reason:  %s" % rep["reason"])
        if rep.get("diff"):
            print(render_diff(rep["diff"]))
    return EXIT[rep["verdict"]]


def add_hookc_parsers(sp):
    h = sp.add_parser("hookc", help="deterministic C hook builds with rshooks-compatible metadata")
    hs = h.add_subparsers(dest="hookc_cmd", required=True)
    s = hs.add_parser("build", help="double-build (per platform twin) -> <index>.hook.wasm + .metadata.json")
    s.add_argument("src", nargs="?", help="source dir: a clean git subtree (its HEAD commit is exported and built) "
                   "unless --allow-unversioned")
    s.add_argument("--git", default=None, help="build the exact committed blobs of REPO at --rev/--path")
    s.add_argument("--rev", default="HEAD")
    s.add_argument("--path", default="")
    s.add_argument("--toolchain", default="kvt-llvm22", choices=sorted(hookc.TOOLCHAINS))
    s.add_argument("--preset", default=None)
    s.add_argument("--param", action="append")
    s.add_argument("--entry", default=None, help="the .c file to compile (toolchains with an entry selector)")
    s.add_argument("--select", default=None, metavar="FILE.c",
                   help="compile only this top-level .c (toolchains without an entry parameter, e.g. "
                        "buildbox-2026-10 / xhc-bin127): the other top-level .c files are withheld from the "
                        "container; recorded as source.entry + source.entry_selector")
    s.add_argument("--platform", action="append", help="linux/arm64, linux/amd64 or all (default: all twins)")
    s.add_argument("--decl", default=None, help="hookc.toml with a [hook] table")
    s.add_argument("--index", type=int, default=None)
    s.add_argument("--hook-name", default=None, help="HookName (UTF-8)")
    s.add_argument("--description", default=None)
    s.add_argument("--on", default=None, help="'all', '' or Payment,Invoke,... (omit: no override)")
    s.add_argument("--can-emit", default=None, help="'' (deny all) or Payment,... (omit: no override)")
    s.add_argument("--no-wce", action="store_true")
    s.add_argument("--allow-unversioned", action="store_true")
    s.add_argument("--out", default=".")
    s.set_defaults(fn=cmd_hookc_build)
    s = hs.add_parser("reproduce", help="rebuild from metadata: REPRODUCED or MISMATCH (+ section diff)")
    s.add_argument("--metadata", required=True)
    s.add_argument("--src", default=None, help="a git work tree whose HEAD:<path> is the sidecar's tree (its commit is exported)")
    s.add_argument("--git", default=None, help="repo clone; the metadata's commit/path is exported")
    s.add_argument("--platform", default=None, help="rebuild only this twin (default: every twin in the sidecar's "
                   "builder.platforms_built, which re-checks that claim)")
    s.add_argument("--wasm", default=None, help="reference wasm (e.g. the published artifact) for the section diff")
    s.add_argument("--no-wce", action="store_true")
    s.add_argument("--out", default=None)
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_hookc_reproduce)


def main(argv=None):
    p = argparse.ArgumentParser(prog="hook-repro", description="Reproducible Xahau hook builds + on-ledger binary check")
    sp = p.add_subparsers(dest="cmd", required=True)

    s = sp.add_parser("recipes", help="list pinned toolchain recipes")
    s.set_defaults(fn=cmd_recipes)

    def recipe_args(s):
        s.add_argument("--recipe", default=None, help="default xhc-bin127, or chosen by --metadata")
        s.add_argument("--metadata", default=None, help="rshooks-build <index>.<fn>.metadata.json sidecar")
        s.add_argument("--preset", default=None, help="recipe preset (e.g. classic, builder-2025)")
        s.add_argument("--param", action="append", help="KEY=VALUE (allowlisted per recipe)")

    s = sp.add_parser("build", help="hermetic build of a source dir")
    s.add_argument("src")
    recipe_args(s)
    s.add_argument("--out", default=None)
    s.set_defaults(fn=cmd_build)

    s = sp.add_parser("verify", help="on-ledger CreateCode vs two clean rebuilds")
    s.add_argument("--hookhash", required=True)
    s.add_argument("--network", default="xahau-mainnet")
    s.add_argument("--src", default=None, help="source dir; with a hookc sidecar: a git work tree whose HEAD:<path> is the sidecar's tree")
    s.add_argument("--git", default=None, help="hookc sidecar only: a repository holding the sidecar's commit")
    recipe_args(s)
    s.add_argument("--out", default=None)
    s.add_argument("--allow-single-operator", action="store_true")
    s.add_argument("--platform", default=None, help="hookc metadata: which platform twin to rebuild on")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_verify)

    s = sp.add_parser("fetch", help="read CreateCode from two operators")
    s.add_argument("--hookhash", required=True)
    s.add_argument("--network", default="xahau-mainnet")
    s.add_argument("--out", default=None)
    s.add_argument("--allow-single-operator", action="store_true")
    s.set_defaults(fn=cmd_fetch)

    s = sp.add_parser("diff", help="section/function diff of two wasm files")
    s.add_argument("a")
    s.add_argument("b")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_diff)

    s = sp.add_parser("bind-review", help="manifest tying a review doc sha256 to a HookHash")
    s.add_argument("review")
    s.add_argument("--hookhash", required=True)
    s.add_argument("--network", default=None)
    s.add_argument("--verify-report", default=None)
    s.add_argument("--out", default=None)
    s.add_argument("--force", action="store_true", help="emit even if coverage/report checks fail (problems stay recorded)")
    s.set_defaults(fn=cmd_bind)

    add_hookc_parsers(sp)

    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except buildmod.BuildError as e:
        print("UNVERIFIED: build error: %s" % e, file=sys.stderr)
        return 3
    except subprocess.TimeoutExpired as e:  # any docker/git step that ran out of time is not a verdict
        print("VERDICT: UNVERIFIED\nreason:  timed out: %s" % e, file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())

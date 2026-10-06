# hook-repro / hookc

Reproducible builds for Xahau Hooks, and a check that the hook installed on-ledger is the binary built
from the source you reviewed.

- `hookc` builds a C Hook twice per platform in fresh, network-less containers with a toolchain pinned by
  digest. It refuses unless every build is byte-identical, and it writes an rshooks-style
  `<index>.hook.metadata.json` sidecar that names the exact git commit and tree it compiled.
- `hook-repro verify` rebuilds from a sidecar (C via hookc, or Rust via rshooks-build) or from a source
  directory. It reads the hook's CreateCode from two RPC endpoints at one validated ledger and returns
  **REPRODUCED**, **MISMATCH** or **UNVERIFIED**.
- `hook-repro bind-review` ties a review document's sha256 to one exact HookHash.

Context: [xahaud #407 "Deterministic Builds for Hooks"](https://github.com/Xahau/xahaud/issues/407). Rust
Hooks get this from rshooks-build's `metadata.json`. This repository does the same for C Hooks and reads
rshooks sidecars too.

> **This is a reproducibility tool. It is not an audit or a certification.** A REPRODUCED verdict means
> "these bytes came from this source with this pinned toolchain". It says nothing about whether the hook is
> correct or safe. See [Stated bounds](#stated-bounds).

## Requirements

- Python **3.11 or newer** (uses `tomllib`). Standard library only. The tests need `pytest`.
- Docker. Builds use pinned public base images from Docker Hub and toolchain artifacts from public URLs
  (GitHub releases, deb.debian.org, raw.githubusercontent.com, static.crates.io), each pinned by sha256 and
  cached in `~/.cache/hook-repro/` (override with `HOOK_REPRO_CACHE`).
- Both `linux/arm64` and `linux/amd64` containers. `hookc-wce` (the WCE tool `hookc` runs) and
  `rshooks-0.2.3` are arm64-only, and `xhc-bin127` is amd64-only, so one host needs emulation for the other
  architecture (Docker Desktop provides it; on Linux install qemu binfmt).
- The first build of a recipe downloads its toolchain. For the LLVM recipes that is about 2 GB.

## Quickstart: verify a deployed hook against its source

The Xahau mainnet ClaimReward-automation hook `805351CE…E9CA` (source
[Ekiserrepe/cron-claimreward-xahau](https://github.com/Ekiserrepe/cron-claimreward-xahau)) with the
sidecar in this repo:

```
git clone https://github.com/Ekiserrepe/cron-claimreward-xahau cr
./hook-repro verify \
  --hookhash 805351CE26FB79DA00647CEFED502F7E15C2ACCCE254F11DEFEDDCE241F8E9CA \
  --git cr --metadata casestudy/hookc/claimreward/0.hook.metadata.json \
  --network xahau-mainnet --out /tmp/cr-verify
echo "exit $?"     # 0 REPRODUCED, 2 MISMATCH, 3 UNVERIFIED, 1 usage error
```

Expected output: `VERDICT: REPRODUCED`, two endpoint reads at one validated ledger, two byte-identical
rebuilds, and the HookDefinition `Fee`/`HookCallbackFee` equal to the WCE that xahaud's own
`validateGuards()` computes. `HookOn` and `HookCanEmit` rows are informational. The definition keeps the
creating SetHook's values, which the installer chooses, not the build.

To make a sidecar for your own C hook:

```
./hookc build --git <repo> --rev <commit> --path <dir> --toolchain hookc-llvm22 --platform all --out out/
# -> out/0.hook.wasm + out/0.hook.metadata.json; publish the sidecar next to the source
```

## Stated bounds

Each of these limits what a verdict means:

- **The evidence comes from one host and one deployed hook.** The public case study shows reproduction for
  1 deployed hook (ClaimReward on Xahau mainnet, read from 2 endpoints) and 1 undeployed build of the same
  source on `hookc-llvm22` (arm64 native + amd64 emulated), plus double builds of two rshooks examples, all on
  one arm64 macOS host running Docker. `kvt-llvm22` has no public case study. This is **not** a claim that C
  hook builds are deterministic in general.
- **amd64 was emulated.** "Byte-identical on amd64" means amd64 binaries under emulation on an arm64
  kernel. It is not evidence about native x86 hardware. A run on native x86_64 Linux is the next step.
- **The Hooks Builder toolchain (`xhc-bin127`) is x86_64-only**, so its cross-architecture determinism
  cannot be tested.
- **ClaimReward's toolchain was reconstructed.** It is one of several equivalent configurations
  (`casestudy/claimreward/matrix.*`). The author did not record a toolchain at build time. Asked
  afterwards (2026-10-01), he recalled the Hooks Toolkit default build server
  (`hook-buildbox.xrpl.org`), but no longer has the machine he built on. That fits the matrix: the
  deployed bytes match clang `-O3` → wasm-opt `-O3` → hook-cleaner, which is the build server's
  2023-era pipeline in Xahau/xrpl-hooks-compiler (`c2wasm-api/src/index.ts` @b8d3692). The Feb 2025
  pipeline in that repo (wasm-opt, hook-cleaner, wasm-opt again; the `builder-2025` preset) does
  NOT match. This is a likely toolchain, not a proven one: the server's deployed history is not public.
- **The chain read is not a proof.** "Two operators" means two different self-reported `pubkey_node`
  values at the same validated ledger hash. That is fingerprint evidence, not proof of independent parties.
  No SHAMap proof is checked.
- **The local Docker daemon and the git binary are trusted.** Downloaded artifacts and cached images are
  re-checked against their pins on every use; build contexts and cargo vendor trees are re-derived from
  those re-checked artifacts, never reused from the cache.
- **Pinned URLs can disappear.** If one does, the build fails closed on its sha256 and the recipe needs a
  mirror.
- **WCE is xahaud's own number** (Guard.h at the pinned commit), never an estimate. It holds for that
  guard-rules version.
- **The `--src` work-tree check** compares file names and bytes under the sidecar's path only. It does not
  compare the executable bit, empty directories or files outside that path, and it is a snapshot taken
  before the build.
- **`bind-review` does not re-verify** the report it binds. It binds the report's sha256 and copies its
  qualifications.

The full design, threat model and the hostile red-team rounds (each finding has a regression test that
fails on the pre-fix commit) are in this README below, `tests/test_rt_round*.py` and `casestudy/hookc/rt-round*/`.

Commit ids named in the evidence and below (for example `ec8eaeb`, `506ba4e`, `cd2c3b7`, `3219828`) are
from the private development history. This public repository starts from one squashed commit of that tree.

## License

MIT (see `LICENSE`). Third-party files and their licenses are listed in `THIRD_PARTY_NOTICES.md`.

---

## Commands

```
hook-repro recipes                                   # pinned toolchains + portable recipe digests
hook-repro build <src-dir> [--recipe R | --metadata M] [--preset P] [--param K=V] [--out DIR]
hook-repro verify --hookhash H --src DIR [--network xahau-mainnet|xahau-testnet] [--recipe R | --metadata M] [--preset P] [--out DIR]
hook-repro fetch  --hookhash H [--network ...] [--out code.wasm]
hook-repro diff a.wasm b.wasm                        # section + function level
hook-repro bind-review review.md --hookhash H [--verify-report verify-report.json] [--out binding.json]
```

Exit codes: `0` REPRODUCED / pass, `2` MISMATCH, `3` UNVERIFIED (read failure, operator disagreement on the
CreateCode or on the validated ledger hash, single-node read, hash mismatch, build failure, non-deterministic
rebuild, a sidecar whose HookHash is not `--hookhash`, unsafe source names, or a review that does not state
the full HookHash), `1` usage error.

`bind-review --verify-report R` copies into the binding what qualifies R's verdict: `network`,
`distinct_operators`, `caveat`, `platforms_built_rechecked`, `platforms_rebuilt`, plus a `caveats` list in
plain words (a single-operator read, a twin not re-checked, HookDefinition `Fee`/`HookCallbackFee` not
compared because the sidecar's WCE is null from `--no-wce`). A `--network` that is not R's network is a
problem (NOT BOUND, exit 3); without `--network` the binding takes R's (RT round 4 F4).

## Trust model of the chain read

`fetch`/`verify` read the HookDefinition from two endpoints. Both reads must be `validated`, at the same
ledger index, with the same ledger hash (the newer endpoint is re-read at the older one's validated
ledger); the report records that index and hash. "Two operators" means the two endpoints reported two
different `pubkey_node` values. That key is self-reported and unauthenticated: it is fingerprint evidence of
which node answered, not proof that two independent parties answered (one proxy or backend can present two
keys). An honest second operator confirms the same validated ledger; a single dishonest backend behind both
hostnames can still answer consistently. No SHAMap proof of the HookDefinition is checked.

## Local trust boundary

- Artifacts in `~/.cache/hook-repro/cas/` are re-hashed against their pin every time they are used.
- A build context is rebuilt from verified artifacts whenever an image has to be built (no `.complete`
  shortcut). A cargo vendor tree is re-derived on every use from the sha256-verified `.crate` artifacts, at
  `vendor/<full 64-hex lock digest>`; a tree or marker file already in the cache is never trusted (RT round 5 P3).
- A docker tag `hook-repro/<recipe>:<digest16>` is used only while it is still bound to the image ID that
  hook-repro recorded when it built it (`~/.cache/hook-repro/images/`); otherwise the build is refused. Both
  builds of a double build must run the same image ID, and the manifest records it. The local docker daemon
  itself is trusted.
- The recipe digest includes `BUILD_ABI` (`hook-repro-build/3`), the version of the hook-repro code that turns
  a recipe into an image and a container run. The manifest records it too. The jail (C recipes) is versioned
  separately as `hook-repro-jail/1` inside those recipes' Dockerfile text, so it is in their digests too.
- Every container gets a unique `--name`; on a timeout or any abnormal exit hook-repro kills that container
  (killing the docker client alone leaves it running) and the result is UNVERIFIED (exit 3).

## What "hermetic" means here

Stated bound: a build's bytes are a function of (pinned image of the twin, `tree_sha256`, params, fixed
env) and nothing else the build host can write. Every input the container can read is either pinned
by digest (image, artifacts, headers) or is the staged source; everything else it sees is created
empty for that one container.

- The base image is pinned by digest. Every downloaded artifact is pinned by sha256 and cached in
  `~/.cache/hook-repro/cas/<sha256>`.
- Builds run with `docker run --network none --read-only` and a tmpfs work dir. The source is first copied
  to a private staging dir without `.git`, `__pycache__` and `.hook-repro` (at any depth); the tree hash is
  computed over that staging dir and only that dir is mounted (read-only, copied to `/work/src`), so
  `tree_sha256` covers exactly the SOURCE files the container receives.
- **The container never sees a host-writable or pre-existing directory** (since `hook-repro-build/3`, RT
  round 3 R3-04). Its only mounts are the staged source (read-only), tmpfs `/work` and `/tmp`, and a FRESH
  EMPTY private `/out` that hook-repro creates for that one container (`run_container` refuses a non-empty
  one); the outputs are copied to `--out` only after the build (a stale file or planted symlink there is
  replaced, never followed or read). A reused `--out`, files planted in it, or a `--out` inside the checkout
  can therefore not reach the bytes. `--out` inside (or equal to) `--src`/`--git`/the built source dir is
  refused (exit 3); a non-empty `--out` is allowed because the container never reads it. The `rshooks`
  recipe additionally mounts its sha256-verified cargo vendor tree read-only.
- Every build sets `SOURCE_DATE_EPOCH=0 TZ=UTC LC_ALL=C` and `-ffile-prefix-map=/work/src/=`, and sorts
  `*.c` inputs in C-locale byte order. clang 15 (`xhc-bin127`) ignores `SOURCE_DATE_EPOCH` (clang honours it
  from 16), so `__DATE__`/`__TIME__`/`__TIMESTAMP__` embedded the build's wall-clock time and two builds on
  the same day passed (RT round 4 F1). That pipeline now passes `-Wno-builtin-macro-redefined
  -D__DATE__="Jan  1 1970" -D__TIME__="00:00:00" -D__TIMESTAMP__="Thu Jan  1 00:00:00 1970"`, exactly what
  clang 22 (`hookc-llvm22`/`kvt-llvm22`) expands under `SOURCE_DATE_EPOCH=0` (observed on both, also through
  token pasting and `push_macro`/`pop_macro`; `#undef __DATE__` then leaves it undefined, a compile error,
  never the builtin). The ClaimReward bytes are unchanged; the recipe digest and `builder.commands` changed.
- **Source names never become arguments.** The C pipelines pass source files to clang as quoted positional
  parameters after `--` (never an unquoted, word-split `$SOURCES` string). Top-level `.c` names must match
  `[A-Za-z0-9._+-]` and not start with `-`, and the listed count must equal `find`'s, else the pipeline exits
  4. `ENTRY` may not start with `-` (recipe allowlist and hookc). hookc's export refuses, in any path
  component, a leading `-`, whitespace, `* ? [ ] { } $ \` ' " \\ ; & | < > ( ) ~ ! # %` and non-printable
  characters (exit 3).
- **The compiler cannot see the build host (C recipes, `"jail": true`).** Docker cannot mask `/proc`
  (runc refuses any mount over or inside it), so each C pipeline runs in `chroot /jail`: a copy of the pinned
  base image's root file system made at image-build time without `/proc`, `/sys`, `/dev` (only a `/dev/null`
  node), `/tmp`, `/run`, `/home`, `/root` and the build host's `/etc/hostname`, `/etc/hosts`,
  `/etc/resolv.conf`; the toolchain is at `/jail/tc`, headers at `/jail/hdr`, and `/jail/work`, `/jail/tmp`
  (tmpfs), `/jail/src` (read-only) and `/jail/out` (fresh, empty, private) are the only mounts. The
  container's own `/sys` is an empty tmpfs as well. `__has_include("/sys/...")` is therefore false and
  `#include "/proc/version"` fails on every host. Before any container runs, a lexical pre-scan also refuses
  sources whose `#include`, `#include_next`, `#import`, `#embed`, `__has_include`, `__has_include_next`,
  `__has_embed` or asm `.incbin` operand is an absolute path or has a `..` component (after line splicing and
  comment removal). The pre-scan is a BELT: a macro-computed operand is not seen by it. The enforcement is
  the jail plus the empty private `/out`: what a relative path can still reach from `/work/src` is the jail's
  own root file system, i.e. the pinned image of that twin. That is deterministic per twin but DIFFERS
  between the arm64 and amd64 twins (e.g. `/usr/lib/<arch>-linux-gnu`, RT3 R3-05), which is why `reproduce`
  and `verify` rebuild every twin in `builder.platforms_built` by default. `JAIL_ABI` (`hook-repro-jail/1`) is in each C
  recipe's Dockerfile text and so in its digest. `rshooks-0.2.3` and `hookc-wce` are not jailed (see below).
- **Why emulated amd64 is not native x86 evidence.** On an arm64 host (Docker Desktop), the `linux/amd64`
  twin runs x86_64 binaries under user-mode emulation on the SAME arm64 kernel. Before the jail, that twin
  even saw the arm64 host's `/sys` (RT round 2 N5: `cpu_capacity`, which x86 kernels do not have), so "both
  twins agree" could be one host's view twice. The jail removes the kernel's files from the compiler's view,
  but the twin's CPU is still the emulator's (instruction semantics, CPUID, floating point and timing), and
  the kernel, libc syscalls and page size are the host's. Any toolchain behaviour that depends on the CPU
  or kernel (for example a CPUID-dependent code path in a compiler, `-march=native`, or a parallelism
  heuristic) is exercised on emulated x86 only. Byte identity of the amd64 twin on an arm64 host is
  therefore evidence about the toolchain under emulation, not about native x86 hardware; a run on native
  x86_64 Linux remains the next step.
- Build parameters are allowlisted per recipe, because their values reach a shell inside the container.
- The manifest (`build-manifest.json`) records the recipe digest, image ID, params, source tree sha256 with
  a per-file listing, the exact commands, per-stage sizes and hashes, and the output sha256 and
  SHA512Half (= HookHash).
- The recipe digest is the portable identity of the toolchain. It hashes the canonical recipe, the pipeline,
  the vendored files and the Dockerfile. The local docker image ID is recorded too, but it is not portable.

## Recipes

| recipe | toolchain | presets |
|---|---|---|
| `buildbox-2026-10` | **Live Hooks Builder** (hook-buildbox.xrpl.org, used by builder.xahau.network and hooks-builder.xrpl.org), matched byte-for-byte 2026-10-06 on 4 sources: the `xhc-bin127` binaries and headers; clang -O3 with wasm-opt on PATH (the clang 15 driver runs `wasm-opt -O3` after the link), one wasm-opt pass (fixed list + -O3), hook-cleaner. Provenance in its `recipe.json`. | `buildbox-2026-10` |
| `xhc-bin127` | Hooks Builder toolchain: xrpl-hooks-compiler v1.27 bin.zip (wasi-sdk clang 15, hook-cleaner, guard_checker), binaryen 108 wasm-opt, xahaud headers @8bcebde | `classic` (clang -O2, wasm-opt -O2, clean), `builder-2025` and `builder-2026-07`: **do not match the live Builder** (checked 2026-10-06; kept for old manifests; the CLI prints a NOTE) |
| `kvt-llvm22` | KVT's deployable-hook pipeline (`build_deploy.sh`): LLVM 22.1.7, binaryen 130, wabt 1.0.41, guard_hoist.py, xahc headers @ec05936 | `deploy` |
| `kvt-llvm22-amd64` | linux/amd64 twin of `kvt-llvm22` (LLVM 22.1.7 X64, binaryen 130 x86_64, wabt 1.0.41 x64, amd64 .debs) | `deploy` |
| `hookc-llvm22` / `-amd64` | hookc canonical C toolchain: the kvt-llvm22 pipeline with official xahaud `hook/*.h` @bb244ef, arm64 + amd64 twins | `deploy` |
| `hookc-wce` | analysis only: xahaud `validateGuards()` WCE (Guard.h @bb244ef) | `default` |
| `rshooks-0.2.3` | Rust Hooks via tequdev/rshooks: `rshooks build` from rshooks-build 0.2.3 (crates.io), rustc 1.89.0, wasm32v1-none | `default` |

### Rust Hooks (`rshooks-<version>`)

rshooks-build writes a `<index>.<fn>.metadata.json` sidecar next to each hook. Its `builder` block records the
rshooks-build version, `rustc -V`, the cargo and rustc arguments and whether wasm-opt ran. Pass that file with
`--metadata`: it selects `rshooks-<version>` and the entry `<index>.<fn>`. Any difference from what the recipe
pins (rustc string, cargo_args, rustc_args, stack size, wasm_opt) is refused with exit 3. There is no nearest match.

```
hook-repro build <src> --metadata 0.main.metadata.json --param CRATE=path/to/crate --param LOCK=Cargo.lock
```

- **Toolchain:** `rust:1.89.0-bookworm` arm64 pinned by digest, plus the wasm32v1-none `rust-std` tarball pinned by
  sha256. rshooks-build is installed during the image build with a `RUN --network=none` step. The command is
  `cargo install --locked --offline`, and its inputs are the published crate plus the 99 crates in its own
  Cargo.lock, each pinned by sha256. `tools/gen_rshooks_recipe.py` generates the recipe from the .crate file.
- **Hook dependencies:** every crates.io package in the source's own `Cargo.lock` (`LOCK`) is fetched from
  static.crates.io and checked against its lockfile `checksum`. The packages are unpacked, on every build,
  into a fresh `directory` vendor tree, which is mounted read-only at `/vendor`. Git sources, other registries and missing
  checksums are refused. The build then runs `--locked --offline` with `--network none`.
- **Fixed build settings:** `SOURCE_DATE_EPOCH=0` and `CARGO_BUILD_JOBS=1`. `--remap-path-prefix` is applied
  for `/work/src`, `/vendor` and `CARGO_HOME`. A source that sets `rustflags` in `.cargo/config*` is refused,
  because the recipe's `RUSTFLAGS` would override them.
- **Sidecar check:** the build fails unless the sidecar's `HookHash` equals the SHA512Half of the bytes the
  build produced.
- **Source trees must not contain symlinks.** The tree hash refuses them. rshooks' own repo symlinks each
  crate's `LICENSE`, so the case study replaces those links with copies of the target.

## C Hooks: `hookc` (deterministic builds + rshooks-compatible metadata)

`./hookc` (= `hook-repro hookc`) is the C counterpart of rshooks-build's `<index>.<fn>.metadata.json`.

```
hookc build --git REPO --rev R --path P [--entry f.c] --toolchain hookc-llvm22|kvt-llvm22|xhc-bin127|buildbox-2026-10 \
            [--platform all] [--on Cron] [--can-emit ClaimReward] [--decl hookc.toml] --out DIR
  -> DIR/<index>.hook.wasm + DIR/<index>.hook.metadata.json
hookc reproduce --metadata M (--git REPO | --src WORKTREE) [--platform P] [--wasm published.wasm]
hook-repro verify --hookhash H (--git REPO | --src WORKTREE) --metadata M [--platform P]  # hookc sidecar
hook-repro verify --hookhash H --src DIR --metadata M                         # rshooks sidecar
```

- **Source = git objects.** A versioned build compiles only the exact committed blobs of `<commit>:<path>`,
  exported from git objects (`hookc build DIR` on a clean work tree exports its HEAD; ignored files,
  skip-worktree edits and eol conversion in the work tree are never compiled). `source.tree_sha256` is computed
  from those git objects. `reproduce` and `verify --metadata` rebuild only from the export of the sidecar's own
  `source.vcs.commit`/`path`: `--git REPO` is any clone holding that commit (only its objects are read, never a
  work tree); `--src WORKTREE` must be a git work tree whose `HEAD:<path>` is `source.vcs.tree` AND whose files
  under `<path>` are byte-identical to the exported blobs (RT round 4 F2): every on-disk file is hashed and
  compared to the blob built, any extra file (untracked, ignored, `__pycache__`, a nested `.git`) or missing
  file, any symlink, and any index entry flagged skip-worktree or assume-unchanged (`git ls-files -v` tag other
  than `H`) is refused (exit 3). `git status` is not trusted for this. The build still uses only the export;
  the check is there because the work tree is what a reviewer reads. They then regenerate the
  ENTIRE sidecar (source block included) from what was built, once per rebuilt twin, and byte-compare it; nothing is copied from the
  given sidecar except the declarations in its `human` block, which are re-validated.
- **Export safety.** Refused (exit 3): absolute, empty, `.` or `..` components, backslash or control
  characters, `.git` in any case, `__pycache__`/`.hook-repro`, names that are not UTF-8, and paths that
  collide under case-folding or Unicode NFC/NFD normalization (they would merge on macOS), git trees whose
  entries are not in git's own order (`git fsck` treeNotSorted; a tree sorts as `name/`), and `.git` (any case)
  or an ignore dir in ANY component of `--path`/`source.vcs.path`. Every file is
  created with `O_EXCL|O_NOFOLLOW` under the export dir, and the written tree is re-listed and must equal
  the git listing byte for byte.
- **Git is only an object store.** Every git call runs with `--no-replace-objects` and
  `GIT_NO_REPLACE_OBJECTS=1`, in an environment with every caller `GIT_*` variable removed (`GIT_DIR`,
  `GIT_OBJECT_DIRECTORY`, `GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_CONFIG*`, `GIT_REPLACE_REF_BASE`, ...),
  `GIT_CONFIG_NOSYSTEM=1` and `HOME`/`XDG_CONFIG_HOME` set to an empty private dir (no system or global
  config or attributes). The commit, EVERY tree and every blob are read raw (`git cat-file --batch`) and
  re-hashed to their ids with the repository's object format (sha1 or sha256); trees are parsed by hookc,
  not `ls-tree`. So `git replace` refs (in the repo, in a `--mirror` clone, or selected via env), planted
  loose objects and a caller's `GIT_DIR` cannot put other bytes under the ids the sidecar names: such
  sidecars end MISMATCH or UNVERIFIED. Repositories with `objects/info/alternates`, `http-alternates` or
  `info/grafts` are refused (exit 3). Shallow clones are accepted: hookc never walks history, and the
  commit is identified by its own re-hashed bytes.
- **The repository's own config is not trusted (RT round 4 H1).** Before any other git command (in
  particular before `git status` on a `hookc build DIR` work tree, which can re-read a file through a filter
  driver), hookc lists the repository's config with `--no-includes` (system and global config are off) and
  refuses (exit 3) any `filter.*`, `include.*`/`includeIf.*` or `core.worktree` key: a filter driver runs a
  command, an include pulls in config hookc cannot see, `core.worktree` moves the work tree being checked. Every
  git call also passes `-c core.fsmonitor=false -c core.useReplaceRefs=false -c core.attributesFile=/dev/null
  -c core.sshCommand=false -c core.pager=cat -c core.untrackedCache=false` (command-line config outranks
  every file) and `GIT_LITERAL_PATHSPECS=1`. hookc runs only rev-parse, cat-file, ls-files, config and status;
  none of them fetches, commits or triggers hooks (`GIT_OPTIONAL_LOCKS=0`: status writes no index).
- **Checkout-converting attributes are refused (exit 3).** hookc compiles the exact blobs, but a
  `.gitattributes` (at the repository root, any directory down to the exported path, or inside it) or
  `$GIT_DIR/info/attributes` that sets `ident`, `filter`, `eol`, `text`/`crlf`, `working-tree-encoding`
  or `export-subst` makes a checkout (what a reviewer reads, or passes as `--src`) differ from those
  blobs. Any pattern counts (hookc does not evaluate which files a pattern matches); `-attr`, `!attr` and
  `binary` are fine. Review the committed bytes with `git show <commit>:<path>`, not a checkout.

- Builds twice per platform twin in fresh `--network none` containers and refuses unless every build is
  byte-identical (within and across linux/arm64 + linux/amd64 where the toolchain has both twins;
  `xhc-bin127` is x86_64-only), and unless every twin's build log states the same `cc`, `wasm_opt_version`,
  `commands` and `wasm_opt` (RT round 5 P1): the sidecar has one `builder` block for all twins.
- Metadata: the same top-level keys and formatting as rshooks sidecars (rshooks-build 0.2.3
  `entry_sidecar.rs` key order, serde pretty JSON + newline), plus a trailing `source` block (git commit +
  tree + content tree sha256 + entry). It is NOT a drop-in rshooks sidecar: `builder` has hookc's own keys
  (`toolchain`, `preset`, `params`, `cc`, `wasm_opt_version`, `commands`, `env`, `platforms`, `wce`; no
  `rustc`/`cargo_args`/`rustc_args`), and hookc writes `"chain": null` where rshooks-build 0.2.3 always
  writes a `ChainSummary` object (`struct`, `description`, `decls` of the Rust chain struct), because a C
  hook has no rshooks chain struct. A consumer that requires rshooks' `chain` object or `builder` keys will
  reject a hookc sidecar. No host paths, times or image IDs, so it is platform-independent. Sources without
  git provenance are refused (`--allow-unversioned` builds, but such metadata is refused by reproduce/verify).
- `HookName`: 2 to 8 Unicode characters or refused (rshooks-build 0.2.3 carriers.rs rule); outside 4..16
  UTF-8 bytes is a warning (rshooks' protocol-window warning).
- `builder.preset` is recorded only when that preset resolves (on every platform twin) to exactly
  `builder.params` apart from the entry parameter; overriding params drops the label to `null`, and a sidecar
  whose label does not resolve to its params is refused.

| sidecar field | Enforced by `reproduce` / `verify --metadata` | how |
|---|---|---|
| `HookHash` | Enforced | = SHA512Half of both rebuilds; `verify`: must equal `--hookhash` (else UNVERIFIED) and the chain's CreateCode |
| `source.vcs`, `tree_sha256`, `file_count` | Enforced | regenerated from the git export actually built |
| `source.entry` | Enforced | must equal the toolchain's entry param in `builder.params` (else refused) |
| `builder.*` (toolchain, platforms digests, params, preset, cc, commands, wasm_opt, env, wce pin) | Enforced | pinned recipe digest must match locally; the rest regenerated from the rebuild and byte-compared, once per rebuilt twin from that twin's own manifest and build log (a twin whose log states another `cc`, `wasm_opt_version`, `commands` or `wasm_opt` is MISMATCH, RT round 5 P1) |
| `builder.platforms_built` | Enforced by `reproduce` and `verify --metadata` without `--platform` | the twins the build actually built (twice each) and byte-compared; `builder.platforms` lists every PINNED twin and is not a build claim. Without `--platform`, `reproduce` and `verify` rebuild EVERY listed twin twice (native and, on another architecture, emulated), every rebuild must be identical (and in `verify` equal to the on-ledger CreateCode), and the claim is regenerated from the twins rebuilt: the report says `platforms_built_rechecked: true`. A listed twin that builds other bytes is MISMATCH. With `--platform P` only P is rebuilt: the report says `platforms_built_rechecked: false` and its reason says `builder.platforms_built` is the original build's record, NOT re-checked |
| `index`, `hook_fn`, `cbak_fn`, `name`, `HookOn`, `HookCanEmit`, `HookName`, `description`, `human` | Enforced | declarations re-validated from `human`, masks recomputed, byte-compared |
| `WCE` | Enforced | recomputed by xahaud validateGuards (pinned) and byte-compared; `verify`: HookDefinition `Fee` must equal `WCE.hook`, and `HookCallbackFee` must equal `WCE.cbak` when `WCE.cbak > 0` and must be ABSENT when `WCE.cbak` is 0, because SetHook writes `Fee` always and `HookCallbackFee` only `if (maxInstrCountCbak > 0)` (xahaud `SetHook.cpp` @bb244ef:1873-1881; `computeExecutionFee` is the identity, `applyHook.cpp` :696-703). An absent field is compared, never skipped (else MISMATCH); only a `null` WCE (a `--no-wce` sidecar) leaves the rows uncompared, and the reason says so. A sidecar that states a WCE is checked only by running the pinned tool: if this run cannot (`--no-wce`, the `hookc-wce` image unusable, a tool error) the verdict is UNVERIFIED (exit 3, "WCE NOT checked"), never MISMATCH: a tool that did not run compared nothing (RT round 4 F3). A `null`-WCE sidecar states no WCE and regenerates as `null` whether or not the tool runs. These are the only enforced definition rows; the verify reason names only the rows actually compared and equal |
| `HookOn` vs HookDefinition | Informational | reported only: SetHook writes the CREATING transaction's HookOn into the definition (xahaud `SetHook.cpp` @bb244ef:1845-1848) and keeps later installers' choices as a per-installation override on the account's Hooks entry (:1630-1640); under featureHookOnV2 a definition may hold HookOnIncoming/HookOnOutgoing and no HookOn. The first installer chooses it, not the build |
| `HookCanEmit` vs HookDefinition | Informational | reported only: the definition keeps the creating SetHook's value, which the installer sets independently of the build |
| `chain` | Informational | always `null` for C hooks |
- `HookOn`/`HookCanEmit` from declarations (`hookc.toml` `[hook]` or flags), encoded like rshooks
  (xahaud `canHook`). Omitted = `null` = no installation override.
- `WCE` = xahaud's own `validateGuards()` (Guard.h @bb244ef, recipe `hookc-wce`), the numbers SetHook stores
  as HookDefinition `Fee`/`HookCallbackFee`, never estimated. If the tool cannot run, `hookc build` writes no
  sidecar (exit 3); only an explicit `--no-wce` writes WCE `null`, and then `builder.wce.reason` is the fixed
  string `WCE not computed (--no-wce)` (RT round 4 F3b: a reason copied from a failed tool run carried a
  local docker image id). `reproduce`/`verify` refuse (exit 3) a sidecar whose WCE is not either two
  non-negative integers with reason `null` or `null` with exactly that reason.
- Evidence: `casestudy/hookc/` (double builds, cross-arch, probes, verify reports). The current sidecars in
  `casestudy/hookc/{claimreward,claimreward-llvm22}/`, the three preset verifies in `casestudy/claimreward/`
  and the bind-review demo there were regenerated for the public release by
  `casestudy/hookc/release-rerun.sh` (outputs in `casestudy/hookc/release/`): hookc 0.5.0, run from the repo
  root, so every path the tool recorded is repo-relative or `$HOOK_REPRO_CACHE/...` (see "Paths in the
  evidence" below). The `hookc-llvm22` recipe digests changed there because the recipe notes were reworded;
  the wasm bytes did not. `casestudy/hookc/rt-round4/` is the hookc 0.5.0 run after the RT round 4 fixes (the
  round-4 reproducers re-run on the fix are in `casestudy/hookc/rt-round4/rt4-scripts-after/`),
  `casestudy/hookc/rt-round3/` the hookc 0.4.0 run,
  `casestudy/hookc/rt-round2/` the hookc 0.3.0 run,
  `casestudy/hookc/rt-round1/` the hookc 0.2.0 run, and the older
  `*-verify.txt`/`*-build.*` files are the hookc 0.1.0 run; both are kept as history. `probes.*` are 0.1.0
  semantics and have not been re-run.

### Paths in the evidence

Build manifests and verify reports record the staged source dir and the output file. Since the public
release they are written as portable paths (`build.portable_path`): under the hook-repro cache as
`$HOOK_REPRO_CACHE/...`, under the current directory relative to it, under the home directory as `~/...`
(`tests/test_public_paths.py`). The release run above was produced that way and is not edited. The
historical runs (`casestudy/hookc/rt-round*/`, the 0.1.0 files, `casestudy/hookc/claimreward-verify/`)
predate that change: absolute host paths in them were replaced by placeholders (`<repo>`, `<scratchpad>`,
`<tmp>`, ...), so they are records of what ran, not files to re-check byte for byte. The development
history also included a case study of a private-source KVT test hook on testnet; it was removed from this
repository, together with every output, reproducer script and log line that named it, and the scripts that
had run it (`rt-round*-rerun.sh`, `probes.sh`) say so in their header.

## Tests

```
python3 -m venv .venv && .venv/bin/pip install pytest
.venv/bin/python -B -m pytest -q -p no:cacheprovider tests   # offline, no Docker needed
HOOK_REPRO_DOCKER_TESTS=1 .venv/bin/python -B -m pytest -q -p no:cacheprovider tests/test_buildbox.py   # opt-in, needs Docker
```

The last line (opt-in, needs docker) rebuilds three Hooks Builder IDE templates with `buildbox-2026-10` and
compares them to outputs recorded from the live service on 2026-10-06 (`tests/fixtures/buildbox/`).

The tests run offline against recorded fixtures: real two-operator RPC responses for the ClaimReward hook,
its 808-byte CreateCode, a real 808-byte near-miss build, and a wat2wasm module. The rshooks tests use rshooks
v0.2.3 `examples/Cargo.lock` and the AcceptAll sidecar printed in the rshooks book. The expected hashes are
literals computed outside the package. `tests/fixtures/rshooks/book_accept_all.metadata.json` is hand-formatted
(transcribed from the rshooks book, not written by rshooks-build), so it is not a formatting reference; the
byte-format reference is the recorded `recorded_firewall_0.main.metadata.json`.
`tests/test_rt_round1.py` holds one regression test per finding of the 2026-09-28 red-team (round 1); docker
is replaced there by a fake container that compiles exactly the directory it is handed.
`tests/test_rt_round2.py` does the same for round 2 (N1 git replace/mirror/env, N2 file-name flag injection and
pipeline quoting, N3 gitattributes, N4 HookOn, N5 host /proc and /sys, N6 platforms_built, N7 timeouts): every
`test_rt2_*` test fails on ec8eaeb; `test_guard_*` tests pin the fixes' edges.
`tests/test_rt_round3.py` does the same for round 3 (R3-01 colon-named exports, R3-02 wasm_opt from the stage
that ran, R3-03/R3-05 verify re-checks every twin, R3-04 the container's out dir, R3-07 git tree order and
reserved path components, R3-08 crash paths, R3-09 HookCallbackFee absence). Where the finding is what the
container can see, docker is replaced at the `docker run` command line by a simulator whose file system is
exactly the command's own `-v` mounts; R3-02 runs every C recipe's real `pipeline.sh` with fake tools. Every
`test_rt3_*` test fails on 506ba4e.
`tests/test_rt_round4.py` does the same for round 4 (F2 `--src` work tree vs the blobs built, F1 clang-15 date
macros, F3/F3b WCE tool failure, F4 bind-review qualifications, H1 the repository's own git config): every
`test_rt4_*` test (27 items) fails on cd2c3b7 (`casestudy/hookc/rt-round4/test_rt_round4_on_cd2c3b7.txt`).
`tests/test_rt5.py` does the same for the round-5 review (P1 every twin's build log compared, P2 `source_vcs` in
the verify report on disk, P3 vendor tree re-derived, P5 bind-review caveat for a `--no-wce` sidecar): every
`test_rt5_*` test fails on 57a8efd.
`tests/test_public_paths.py` pins the portable paths in manifests and verify reports (both tests fail on the
code before that change).

Case study: `casestudy/`. `tools/mutants.py` lists the mutants used for mutation testing (the runner is not included).

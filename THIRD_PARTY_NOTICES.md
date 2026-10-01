# Third-party material

The MIT license in `LICENSE` covers the code in this repository. It does not cover the files below,
which keep their own licenses.

| path | origin | license |
|---|---|---|
| `casestudy/claimreward/src/claimReward.c`, `tests/fixtures/hookc/claimreward_installHook.js` | [Ekiserrepe/cron-claimreward-xahau](https://github.com/Ekiserrepe/cron-claimreward-xahau) | The repository has no LICENSE file; its `package.json` declares `"license": "MIT"` |
| `tests/fixtures/claimreward_onledger.wasm`, `tests/fixtures/claimreward_nearmiss_808.wasm`, and the ClaimReward builds and `onledger.wasm` copies under `casestudy/claimreward/` and `casestudy/hookc/` (`claimreward*/`, `release/`, `rt-round*/`) | compiled from the file above (the onledger copies were read from Xahau mainnet) | as above |
| `tests/fixtures/hookc/tts.h` | [Xahau/xahaud](https://github.com/Xahau/xahaud) `hook/tts.h` | ISC |
| `tests/fixtures/rshooks/*` | [tequdev/rshooks](https://github.com/tequdev/rshooks) v0.2.3 (`examples/Cargo.lock`, the rshooks book, a recorded rshooks-build sidecar) | MIT |
| `casestudy/rshooks/**` | build logs and manifests of tequdev/rshooks examples | MIT (rshooks) |

Not vendored. These are downloaded at build time from their upstream URLs, pinned by sha256, and keep their
own licenses: LLVM (Apache-2.0 WITH LLVM-exception), binaryen and wabt (Apache-2.0), xahaud headers and
`Guard.h` (ISC), xrpl-hooks-compiler `bin.zip` (GitHub detects no license for that repository; its contents carry their own licenses), Debian
packages, the Rust toolchain and crates.io crates (each under its own license).

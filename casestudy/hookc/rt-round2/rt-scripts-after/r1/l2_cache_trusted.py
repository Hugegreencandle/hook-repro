# L2: the local cache is trusted without re-verification. fetch_artifact returns an existing CAS file without
# re-hashing it; prepare_context trusts a `.complete` sentinel; ensure_image uses ANY local image carrying the tag
# hook-repro/<recipe>:<digest16>. A tampered cache/daemon yields manifests that still show the pinned recipe digest.
# (Demo uses a scratch HOOK_REPRO_CACHE; the docker-tag case is by code reading, build.py:263-273, not executed.)
import os, sys, tempfile
os.environ["HOOK_REPRO_CACHE"] = tempfile.mkdtemp(dir=".")
sys.path.insert(0, '../rt-hookc')
from hook_repro import build as B
a = {"name": "x", "url": "https://example.invalid/x", "sha256": "ab" * 32}
p = os.path.join(B.CACHE, "cas", a["sha256"]); os.makedirs(os.path.dirname(p)); open(p, "w").write("NOT THE PINNED BYTES")
print("fetch_artifact returned", B.fetch_artifact(a) == p, "without verifying; sha256 of it =", B.sha256_file(p)[:16], "!= pinned", a["sha256"][:16])

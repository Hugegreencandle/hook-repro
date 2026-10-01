#!/bin/sh
# R3-06: what the jailed pipeline sees: the exact docker run flags of build.run_container
# (hookc-llvm22), with the pipeline replaced by a probe. Informational (jail inventory).
set -u
RT=$(cd "$(dirname "$0")" && pwd); HR=$RT/../rt3-hookc; W=$RT/work-r3-06; rm -rf "$W"; mkdir -p "$W/src" "$W/out"
echo 'int x;' > "$W/src/hook.c"; echo stale > "$W/out/left-over-from-a-previous-run"
IMG=$(cd "$HR" && python3 -c "
from hook_repro import build as b; r=b.load_recipe('hookc-llvm22'); print(b.ensure_image(r, lambda *_: None)['image_id'])")
echo "image $IMG"
docker run --rm --network none --platform linux/arm64 --read-only --tmpfs /jail/work:exec,size=1g --tmpfs /jail/tmp:exec,size=256m \
  -v "$W/src:/jail/src:ro" -v "$W/out:/jail/out" --tmpfs /sys:ro,size=4k -e SOURCE_DATE_EPOCH=0 -e TZ=UTC -e LC_ALL=C -e ENTRY= \
  "$IMG" chroot /jail /bin/sh -c '
echo "## env"; env | sort
echo "## /"; ls /
echo "## /dev"; ls -la /dev
echo "## /proc /sys"; ls -d /proc /sys 2>&1
echo "## /out (host dir, rw)"; ls -la /out
echo "## from cwd /work/src: ../../out and ../../usr/lib"; mkdir -p /work/src; cd /work/src; ls ../../out; ls -d ../../usr/lib/*-linux-gnu
echo "## open fds"; ls /dev/fd 2>&1; echo "## /etc host files"; ls /etc/hostname /etc/hosts /etc/resolv.conf /etc/mtab 2>&1
echo "## clang config/env knobs"; ls /tc/llvm/bin/*.cfg 2>&1; echo HOME=$HOME; ls -d $HOME 2>&1
'

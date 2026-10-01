#!/bin/sh
W=<scratchpad>/probes
SRC="$W/other user/deep path/cr"
run() { n=$1; img=$2; plat=$3; shift 3; o=$W/user-$n; rm -rf "$o"; mkdir -p "$o"; chmod 777 "$o"
  docker run --rm --network none --platform $plat --read-only --tmpfs /work:exec,size=1g,mode=1777 --tmpfs /tmp:exec,mode=1777 \
    --user 4242:4242 -e HOME=/tmp -e USER=mallory -e TZ=Asia/Tokyo -e LC_ALL=ja_JP.UTF-8 -e LANG=ja_JP.UTF-8 -e SOURCE_DATE_EPOCH=1700000000 \
    -v "$SRC:/src:ro" -v "$o:/out" "$@" $img /bin/sh /tc/pipeline.sh
  echo "$n rc=$? $(shasum -a 512 "$o/hook.wasm" 2>/dev/null | cut -c1-16)"; }
run xhc sha256:cbfd50d71f185cbd6fe2db77b1a605198d27cd8bb90ce2b8e50204a6dc8fb8f8 linux/amd64 -e CLANG_OPT=-O2 -e WASMOPT=-O2 -e STAGES=opt,clean
run llvm-arm64 sha256:5e321e71441014322b03c5200a28bb31f7e86fd0b7316a75f3450bfe9dc94f93 linux/arm64 -e ENTRY=claimReward.c

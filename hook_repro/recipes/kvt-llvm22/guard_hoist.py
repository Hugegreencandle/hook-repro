#!/usr/bin/env python3
# guard_hoist.py <in.wasm> <out.wasm>
#
# Xahau SetHook guard-checker (xahaud include/xrpl/hook/Guard.h) requires the byte
# immediately after every `loop <blocktype>` to be i32.const (0x41), i.e. the guard
# triple  `i32.const ID; i32.const MAXITER; call _g`  must be the FIRST thing in the
# loop.  wasm-opt --rereloop occasionally emits `loop { block { guard; body } }` for
# loops that contain a continue/br region, trapping the guard one level deep -> the
# checker returns "Missing first i32.const after loop instruction" -> temMALFORMED.
#
# This pass rotates the 2-byte `block` header to AFTER the guard triple, yielding
# `loop { guard; block { body } }`.  This is provably semantics-preserving:
#   * it does not change block nesting depth or ordering, so every branch label
#     (relative depth) still resolves to the same block/loop,
#   * it does not change any local index or immediate,
#   * it does not change the code-section byte length (pure in-place rotation),
#     so no LEB size prefixes anywhere in the module change.
# The guard call has no operands and no branch-target dependence, so hoisting the
# three guard instructions above the (empty-header) block cannot alter execution.
#
# It ONLY touches loops whose exact next bytes are  02 40  41.. 41.. 10 00  (block,
# then a well-formed guard triple calling import func 0).  Anything else is left
# untouched, so a conforming build is a no-op.
import sys, subprocess, re

def leb_len(b, i, signed):
    # return number of bytes of the LEB128 starting at b[i]
    n = 0
    while True:
        byte = b[i + n]; n += 1
        if byte & 0x80 == 0:
            break
    return n

def find_bad_loops(path):
    dis = subprocess.run(['wasm-objdump', '-d', path], capture_output=True, text=True).stdout
    lines = [l for l in dis.splitlines() if re.match(r'\s*[0-9a-f]+:\s+[0-9a-f]', l)]
    offs = []
    for idx, l in enumerate(lines):
        if re.search(r'\|\s*loop\b', l):
            n1 = lines[idx+1] if idx+1 < len(lines) else ''
            n2 = lines[idx+2] if idx+2 < len(lines) else ''
            n3 = lines[idx+3] if idx+3 < len(lines) else ''
            ok = ('i32.const' in n1) and ('i32.const' in n2) and ('call 0' in n3)
            if not ok:
                offs.append(int(l.strip().split(':')[0], 16))
    return offs

def main():
    src, dst = sys.argv[1], sys.argv[2]
    data = bytearray(open(src, 'rb').read())
    bad = find_bad_loops(src)
    patched = 0
    for off in bad:
        # expect: 03 <bt> 02 40 41 <sleb> 41 <sleb> 10 00
        assert data[off] == 0x03, f"off {hex(off)} not loop"
        # loop blocktype: single byte 0x40 or a value type (0x7C-0x7F etc.) -> 1 byte here
        bt = off + 1
        assert data[bt] == 0x40, f"unexpected loop blocktype {data[bt]:#x} at {hex(off)}"
        blk = bt + 1                      # block opcode
        assert data[blk] == 0x02, f"expected block(0x02) at {hex(blk)} got {data[blk]:#x}"
        assert data[blk+1] == 0x40, f"expected block void type at {hex(blk+1)}"
        g = blk + 2                       # guard triple start
        assert data[g] == 0x41, "guard i32.const #1 missing"
        p = g + 1 + leb_len(data, g+1, True)
        assert data[p] == 0x41, "guard i32.const #2 missing"
        p = p + 1 + leb_len(data, p+1, False)
        assert data[p] == 0x10, "guard call missing"
        p = p + 1 + leb_len(data, p+1, False)  # p = end of guard call (exclusive)
        # _g returns i32; the guard statement drops it. Include the trailing
        # drop so the hoisted chunk is stack-neutral above the block.
        if data[p] == 0x1a:                    # drop
            p += 1
        block_hdr = bytes(data[blk:blk+2])     # 02 40
        guard = bytes(data[g:p])               # guard triple (+ drop)
        # rotate: [block_hdr][guard] -> [guard][block_hdr]
        data[blk:p] = guard + block_hdr
        patched += 1
    open(dst, 'wb').write(data)
    print(f"guard_hoist: patched {patched} loop(s): {[hex(o) for o in bad]}")

if __name__ == '__main__':
    main()

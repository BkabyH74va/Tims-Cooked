#!/usr/bin/env python3
"""Decode the IOSurfaceRootUserClient 2022 dispatch table, validating the layout."""
import struct

K = r'G:/REPO\tools\opencode-temp\iosurface-extract\com.apple.iokit.IOSurface'
B = open(K, 'rb').read()
BASE = 0xFFFFFE0007004000
TBL = 0x46638

# known handler VAs (from the disassembly) used to validate the layout
KNOWN = {
    0x11: 0xfffffe000a3498f4,
    0x12: 0xfffffe000a34991c,
    0x13: 0xfffffe000a349934,
}

def s32(v):
    return v - 0x100000000 if v & 0x80000000 else v

print('%-4s %-18s %-18s %-18s %-18s %-18s' % ('sel', 'A: r8,sIn,stIn,sOut,stOut', 'B: 2022', 'handler', 'known', ''))
for i in range(24):
    o = TBL + i * 0x28
    if o + 0x28 > len(B):
        break
    raw = B[o:o + 0x28]
    a = struct.unpack_from('<Q', raw, 0)[0]
    f8, fC, f10, f14, f18, f1C = struct.unpack_from('<IIIIII', raw, 8)
    h = BASE + (a & 0xFFFFFFFF)
    known = KNOWN.get(i)
    mark = ''
    if known:
        mark = 'MATCH' if h == known else 'MISMATCH(exp %x)' % known
    print('%-4d %-18s %-18s handler=0x%x %s' % (
        i,
        '%d,%d,%d,%d' % (f8, f10, f14, f18),
        '%d,%d,%d,%d flags=%d' % (f10, f14, f18, f1C, fC),
        h, mark))
    if known and h == known:
        print('     raw: %s' % raw.hex())

#!/usr/bin/env python3
"""Locate dispatch-table references to handler VAs, tolerating PAC-signed pointers."""
import struct, sys

P = r'G:/REPO\tools\opencode-temp\iosurface-extract\com.apple.iokit.IOSurface'
B = open(P, 'rb').read()
TEXT_OFF = 0x8000
TEXT_ADDR = 0xfffffe000a3257c0
TEXT_SIZE = 0x3461c

targets = [int(a, 16) for a in sys.argv[1:]]
MASK = 0x00FFFFFFFFFFFFFF

hits = {}
n = len(B) // 8
for i in range(n):
    w = struct.unpack_from('<Q', B, i * 8)[0]
    c = w & MASK
    for t in targets:
        if c == (t & MASK):
            hits.setdefault(t, []).append(i * 8)

for t in targets:
    offs = hits.get(t, [])
    print('=== handler %s : %d refs ===' % (hex(t), len(offs)))
    for j in offs:
        print('  fileoff %#x' % j)
        base = j - 0x30
        for k in range(0, 0x90, 8):
            w = struct.unpack_from('<Q', B, base + k)[0]
            mark = ''
            if base + k == j:
                mark += '  <<< HANDLER'
            if (w & MASK) in [(x & MASK) for x in targets]:
                mark += '  <<< TARGET'
            print('    %+04x: %016x%s' % (k - 0x30, w, mark))
        print()

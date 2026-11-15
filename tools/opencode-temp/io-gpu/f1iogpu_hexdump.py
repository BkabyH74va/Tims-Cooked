import struct, sys

KC = r"G:/REPO\firmware\24A446\kernelcache.release.macho"
d = open(KC, 'rb').read()
BASE = 0xfffffe0007000000

SEGS = [
    ('__TEXT',         0xfffffe0007004000, 0x0,       0x8000),
    ('__PRELINK_TEXT', 0xfffffe000700c000, 0x8000,    0xdc8000),
    ('__DATA_CONST',   0xfffffe0007dd4000, 0xdd0000,  0x678000),
    ('__DATA_SPTM',    0xfffffe000844c000, 0x1448000, 0x4c000),
    ('__TEXT_EXEC',    0xfffffe0008498000, 0x1494000, 0x2fb0000),
    ('__TEXT_BOOT_EXEC',0xfffffe000b448000,0x4444000, 0x8000),
    ('__PRELINK_INFO', 0xfffffe000b450000, 0x444c000, 0x26c000),
    ('__DATA',         0xfffffe000b6bc000, 0x46b8000, 0x308000),
    ('__LINKEDIT',     0xfffffe000b9c4000, 0x49c0000, 0xc4000),
]
def va2off(va):
    for name, vm, off, size in SEGS:
        if vm <= va < vm+size:
            return off + (va-vm)
    return None

start = int(sys.argv[1], 0)
end = int(sys.argv[2], 0)
off = va2off(start)
for va in range(start, end, 8):
    raw, = struct.unpack_from('<Q', d, va2off(va))
    lo, hi = raw & 0xFFFFFFFF, (raw >> 32) & 0xFFFFFFFF
    cand = BASE + lo
    print('0x%x  raw=0x%016x  lo32=0x%08x hi32=0x%08x  base+lo=0x%x' % (va, raw, lo, hi, cand))

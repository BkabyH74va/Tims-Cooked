import struct, sys

KC = r"G:/REPO\firmware\24A446\kernelcache.release.macho"
d = open(KC, 'rb').read()
BASE = 0xfffffe0007004000
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
count = int(sys.argv[2], 0)
stride = int(sys.argv[3], 0) if len(sys.argv) > 3 else 40

for i in range(count):
    va = start + i*stride
    o = va2off(va)
    if o is None:
        print('%3d va=0x%x  (unmapped)' % (i, va)); continue
    raw, = struct.unpack_from('<Q', d, o)
    fn = BASE + (raw & 0xFFFFFFFF)
    f = struct.unpack_from('<6I', d, o+8)
    extra = struct.unpack_from('<2Q', d, o+32) if stride >= 48 else (0,0)
    print('%3d table+0x%03x va=0x%x  fn=0x%x  fields=%s  extra=%s  rawhi=0x%08x' % (
        i, i*stride, va, fn, ['0x%x' % x for x in f], ['0x%x'%x for x in extra], (raw>>32)&0xFFFFFFFF))

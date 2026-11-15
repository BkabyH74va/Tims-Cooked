import struct

KC = r"G:/REPO\firmware\24A446\kernelcache.release.macho"
d = open(KC, 'rb').read()

# flat segments
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
            return off + (va-vm), name
    return None, None

def off2va(off):
    for name, vm, o, size in SEGS:
        if o <= off < o+size:
            return vm + (off-o), name
    return None, None

if __name__ == '__main__':
    # IOSurface __mod_init_func @ vm 0xfffffe000837d3d8 size 0x90
    for va, size, label in [(0xfffffe000837d3d8, 0x90, 'IOSurface __mod_init_func')]:
        off, seg = va2off(va)
        print('%s va=0x%x -> kc off 0x%x (%s)' % (label, va, off, seg))
        for i in range(size//8):
            raw, = struct.unpack_from('<Q', d, off+i*8)
            print('  [%2d] @0x%x raw=0x%016x' % (i, va+i*8, raw))

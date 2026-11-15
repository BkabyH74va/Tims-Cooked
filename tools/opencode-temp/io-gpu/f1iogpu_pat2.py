import struct, sys

KC = r"G:/REPO\firmware\24A446\kernelcache.release.macho"
d = open(KC, 'rb').read()
LC_FILESET_ENTRY = 0x80000035
LC_SEGMENT_64 = 0x19

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

magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, _ = struct.unpack_from('<IiiIIIII', d, 0)
off = 32
entries = []
for i in range(ncmds):
    cmd, cmdsize = struct.unpack_from('<II', d, off)
    if cmd == LC_FILESET_ENTRY:
        vmaddr, fileoff = struct.unpack_from('<QQ', d, off+8)
        noff = off+32
        name = d[noff:d.index(b'\0', noff)].decode('ascii', 'replace')
        entries.append((name, vmaddr, fileoff))
    off += cmdsize

def member_sections(fileoff):
    m = struct.unpack_from('<IiiIIIII', d, fileoff)
    n = m[4]
    o = fileoff+32
    segs = []
    for _ in range(n):
        cmd, cs = struct.unpack_from('<II', d, o)
        if cmd == LC_SEGMENT_64:
            nm = d[o+8:o+24].split(b'\0')[0].decode()
            vmaddr, vmsize, foff, fsize = struct.unpack_from('<QQQQ', d, o+24)
            nsects, = struct.unpack_from('<I', d, o+64)
            so = o+72
            for _i in range(nsects):
                sn = d[so:so+16].split(b'\0')[0].decode()
                sg = d[so+16:so+32].split(b'\0')[0].decode()
                sa, ss, soff = struct.unpack_from('<QQI', d, so+32)
                segs.append((sg, sn, sa, ss, soff))
                so += 80
        o += cs
    return segs

target_name = sys.argv[1]
pat = struct.pack('<I', int(sys.argv[2], 0))
for name, vmaddr, fileoff in entries:
    if name != target_name:
        continue
    for sg, sn, sa, ss, soff in member_sections(fileoff):
        blob = d[soff:soff+ss]
        idx = 0
        while True:
            i = blob.find(pat, idx)
            if i < 0:
                break
            print('  %s.%s va=0x%x  pattern at va=0x%x (kc off 0x%x)' % (sg, sn, sa, sa+i, soff+i))
            # show context
            lo = max(0, i-32)
            ctx = blob[lo:i+36]
            print('    ctx: ' + ' '.join('%02x' % b for b in ctx))
            idx = i+1

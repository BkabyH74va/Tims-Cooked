import struct, re, sys

KC = r"G:/REPO\firmware\24A446\kernelcache.release.macho"
d = open(KC, 'rb').read()
LC_FILESET_ENTRY = 0x80000035
LC_SEGMENT_64 = 0x19

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


def member_segs(fileoff):
    m = struct.unpack_from('<IiiIIIII', d, fileoff)
    n = m[4]
    o = fileoff+32
    segs = []
    for _ in range(n):
        cmd, cs = struct.unpack_from('<II', d, o)
        if cmd == LC_SEGMENT_64:
            nm = d[o+8:o+24].split(b'\0')[0].decode()
            vmaddr, vmsize, foff, fsize = struct.unpack_from('<QQQQ', d, o+24)
            segs.append((nm, vmaddr, vmsize, foff, fsize))
        o += cs
    return segs


rows = []
for name, vmaddr, fileoff in entries:
    segs = member_segs(fileoff)
    te = [s for s in segs if s[0] == '__TEXT_EXEC']
    tvm = tvs = 0
    if te:
        tvm, tvs = te[0][1], te[0][2]
    rows.append((name, fileoff, tvm, tvs))

rows.sort(key=lambda r: r[0])
for name, fo, tvm, tvs in rows:
    print('%-70s fileoff=0x%08x  texec=0x%012x size=0x%x' % (name, fo, tvm, tvs))

print('\n--- GPU-ish names ---')
pat = re.compile(r'agx|gpu|graphics|display|metal|coremedia|iomobilefb|dcp', re.I)
for name, fo, tvm, tvs in rows:
    if pat.search(name):
        print('%-70s fileoff=0x%08x  texec=0x%012x size=0x%x' % (name, fo, tvm, tvs))

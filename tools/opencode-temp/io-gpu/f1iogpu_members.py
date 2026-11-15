import struct, sys

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

print('fileset entries', len(entries))

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
    if te:
        rows.append((te[0][1], te[0][2], name, fileoff))
rows.sort()
print('members with __TEXT_EXEC:', len(rows))

target = 0xfffffe000a325000
lo = None
for vm, vs, name, fo in rows:
    if vm <= target < vm+vs:
        lo = (vm, vs, name, fo)
print('\nowner of 0x%x:' % target, lo)

# neighbours
for vm, vs, name, fo in rows:
    if abs(vm - target) < 0x20000:
        print('  0x%012x - 0x%012x  %s' % (vm, vm+vs, name))

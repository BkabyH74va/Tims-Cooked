import struct, sys, re

path = r'G:/REPO\tools\opencode-temp\f1-iosurface\dsc\IOSurface'
d = open(path, 'rb').read()
magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, res = struct.unpack_from('<IiiIIIII', d, 0)
segs = []
off = 32
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from('<II', d, off)
    if cmd == 0x19:
        segname = d[off+8:off+24].rstrip(b'\0').decode()
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from('<QQQQ', d, off+24)
        segs.append((segname, vmaddr, vmsize, fileoff, filesize))
    off += cmdsize

def vm2off(vm):
    for name, va, vsz, fo, fs in segs:
        if va <= vm < va + vsz and fs > 0:
            return fo + (vm - va)
    return None

def cstr(vm):
    o = vm2off(vm)
    if o is None: return None
    e = d.find(b'\0', o)
    return d[o:e].decode('utf-8', 'replace')

# string references used by the connect block (from the disassembly)
refs = [0x1eda0a798, 0x1eda0a7b8, 0x1eda0a258, 0x1eda0a278, 0x1eda0a298]
print("== referenced strings ==")
for r in refs:
    print("  %#x -> %r" % (r, cstr(r)))

# dump all cstrings in __AUTH_CONST region 0x1eda0a000..0x1eda0e000
print("\n== all strings in __AUTH_CONST ==")
for name, va, vsz, fo, fs in segs:
    if name != '__AUTH_CONST': continue
    blob = d[fo:fo+fs]
    i = 0
    while i < len(blob):
        if blob[i] == 0:
            i += 1; continue
        j = blob.find(b'\0', i)
        s = blob[i:j]
        if len(s) >= 3 and all(32 <= c < 127 for c in s):
            print("  %#018x %r" % (va + i, s.decode()))
        i = j + 1

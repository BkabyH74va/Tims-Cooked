import struct, re

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

def rd64(vm):
    o = vm2off(vm)
    if o is None: return None
    return struct.unpack_from('<Q', d, o)[0]

def cstr(vm):
    o = vm2off(vm)
    if o is None: return None
    e = d.find(b'\0', o)
    if e < 0 or e - o > 200: return None
    s = d[o:e]
    if not all(32 <= c < 127 for c in s): return None
    return s.decode()

# scan __AUTH_CONST for CFString records: isa, flags, char*, length
for name, va, vsz, fo, fs in segs:
    if name not in ('__AUTH_CONST', '__DATA_CONST'): continue
    print("== CFStrings in %s ==" % name)
    seen = set()
    for i in range(0, fs - 32, 8):
        vm = va + i
        isa = rd64(vm)
        flags = rd64(vm + 8)
        cptr = rd64(vm + 16)
        ln = rd64(vm + 24)
        if isa is None or cptr is None or ln is None: continue
        if not (0x100000000 < isa < 0x200000000): continue
        if ln == 0 or ln > 200: continue
        s = cstr(cptr)
        if not s: continue
        if s in seen: continue
        seen.add(s)
        print("  %#018x  %r" % (vm, s))

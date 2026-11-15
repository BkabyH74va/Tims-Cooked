#!/usr/bin/env python3
import struct, re, sys

KEXT = "/Users/USER/iosurface-kext/com.apple.iokit.IOSurface"
DIS  = "/Users/USER/iosurface-kext/dis.txt"

B = open(KEXT, "rb").read()
ncmds = struct.unpack_from("<I", B, 16)[0]
off = 32
segs = []
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", B, off)
    if cmd == 0x19:
        segname = B[off+8:off+24].rstrip(b"\0").decode()
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", B, off+24)
        segs.append((segname, vmaddr, vmsize, fileoff, filesize))
    off += cmdsize

def vma(fileoff):
    for name, va, vs, fo, fs in segs:
        if fo <= fileoff < fo+fs:
            return va + (fileoff-fo)
    return None

def foff(vmaddr):
    for name, va, vs, fo, fs in segs:
        if va <= vmaddr < va+vs:
            return fo + (vmaddr-va)
    return None

print("=== segments ===")
for s in segs:
    print(f"  {s[0]:14s} vm=0x{s[1]:x} size=0x{s[2]:x} file=0x{s[3]:x} fsize=0x{s[4]:x}")

TBL_FILE = 0x46638
TBL_VMA = vma(TBL_FILE)
print(f"\n=== dispatch table file 0x{TBL_FILE:x} -> vm 0x{TBL_VMA:x} ===")

# dump raw qwords of the table with both alignments
print("\n=== raw qwords 0x46610..0x46790 ===")
for o in range(0x46610, 0x46790, 8):
    q = struct.unpack_from("<Q", B, o)[0]
    lo = q & 0xffffffff
    hi = q >> 32
    print(f"  0x{o:06x}  q=0x{q:016x}  lo=0x{lo:08x}  hi=0x{hi:08x}")

# find error-string addresses
strings = [
    b"IOSurface: compressed plane[%d] Data region overlaps header region",
    b"IOSurface: kIOSurfacePlaneHeaderRegionBytesPerSlice %d exeeds maximum value.",
    b"IOSurface: kIOSurfacePlaneDataRegionBytesPerSlice %d exceeds maximum value.",
]
print("\n=== strings -> vmaddr ===")
svm = {}
for s in strings:
    i = B.find(s)
    if i < 0:
        print(f"  NOT FOUND: {s[:40]!r}")
        continue
    v = vma(i)
    svm[s] = v
    print(f"  file 0x{i:x} vm 0x{v:x}  {s[:60]!r}")

# load disassembly
lines = open(DIS, "r", errors="replace").read().splitlines()
def parse_addr(l):
    m = re.match(r"\s*(fffffe[0-9a-f]+):", l)
    return int(m.group(1),16) if m else None

# index disassembly by address
addr_lines = []
for l in lines:
    a = parse_addr(l)
    if a is not None:
        addr_lines.append((a, l))

print("\n=== adrp/add xrefs to target strings ===")
for s, target in svm.items():
    page = target & ~0xfff
    pagestr = f"0x{page:x}"
    hits = []
    for i, (a, l) in enumerate(addr_lines):
        if "adrp" in l and pagestr in l:
            # look ahead up to 6 insns for add with matching low bits
            lo = target & 0xfff
            for j in range(i, min(i+7, len(addr_lines))):
                a2, l2 = addr_lines[j]
                if "add" in l2 and f"#0x{lo:x}" in l2:
                    hits.append((a, l, a2, l2))
                    break
    print(f"\n-- {s[:55]!r} target=0x{target:x} hits={len(hits)}")
    for h in hits[:12]:
        print(f"   adrp@0x{h[0]:x}: {h[1].strip()}")
        print(f"   add @0x{h[2]:x}: {h[3].strip()}")

# print function starts: find bti c / pacibsp preceded by ret
print("\n=== nearby function starts (bti c) around table handler candidates ===")
for a, l in addr_lines:
    if 0xfffffe000a344000 <= a <= 0xfffffe000a347000 and ("bti" in l and "c" in l):
        print(f"  0x{a:x}: {l.strip()}")

#!/usr/bin/env python3
import re
dis = "/Users/USER/iosurface-kext/dis.txt"
lines = open(dis).read().splitlines()
B = open("/Users/USER/iosurface-kext/com.apple.iokit.IOSurface","rb").read()

# cstring: addr 0xfffffe0007a18ea8 <-> file offset 1816
def cstr_at(addr):
    off = 1816 + (addr - 0xfffffe0007a18ea8)
    if off < 0 or off >= len(B): return "<bad>"
    end = B.find(b"\0", off)
    return B[off:end].decode("utf-8","replace")

print("=== strings referenced in the parser ===")
for imm in [0x3da,0x3f6,0x40d,0x424,0x436,0x449,0xe9,0x33]:
    a = 0xfffffe0007a1a000 + imm
    print(f"  pageA+0x{imm:x} = {a:#x} : {cstr_at(a)}")
for imm in [0xb9a,0xb50,0xb34,0xc68,0xd32,0x79c,0xff9]:
    a = 0xfffffe0007a19000 + imm
    print(f"  page190+0x{imm:x} = {a:#x} : {cstr_at(a)}")

print("\n=== parser region a32cc00..a32cdb8 ===")
for i, l in enumerate(lines):
    m = re.match(r'\s*(fffffe000a32c[bc][0-9a-f]{2}):', l)
    if m:
        addr = int(m.group(1), 16)
        if 0xa32cc00 <= addr <= 0xa32cdb8:
            print(l.strip())

print("\n=== error blocks ===")
for lo_a, hi_a in [(0xa32e180,0xa32e1d0),(0xa32e440,0xa32e4d0)]:
    print(f"--- {lo_a:#x}..{hi_a:#x} ---")
    for i, l in enumerate(lines):
        m = re.match(r'\s*(fffffe000a3[0-9a-f]+):', l)
        if m:
            addr = int(m.group(1), 16)
            if lo_a <= addr <= hi_a:
                print(l.strip())

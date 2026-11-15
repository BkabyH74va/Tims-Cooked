#!/usr/bin/env python3
import re
dis = "/Users/USER/iosurface-kext/dis.txt"
lines = open(dis).read().splitlines()
B = open("/Users/USER/iosurface-kext/com.apple.iokit.IOSurface","rb").read()

def cstr_at(addr):
    off = 1816 + (addr - 0xfffffe0007a18ea8)
    if off < 0 or off >= len(B): return "<bad>"
    end = B.find(b"\0", off)
    return B[off:end].decode("utf-8","replace")

print("=== strings used in the slice block ===")
for a in [0xfffffe0007a1a000+0xd, 0xfffffe0007a1a000+0x33,
          0xfffffe0007a1d000+0x9d0, 0xfffffe0007a1d000+0xb31,
          0xfffffe0007a1d000+0xb75, 0xfffffe0007a1d000+0xbc3,
          0xfffffe0007a1d000+0xc1f,
          0xfffffe0007a19000+0xd8c, 0xfffffe0007a19000+0xdbb,
          0xfffffe0007a19000+0x7c4]:
    print(f"  {a:#x} : {cstr_at(a)}")

def in_range(l, lo, hi):
    m = re.match(r'\s*(fffffe[0-9a-f]+):', l)
    if not m: return False
    a = int(m.group(1), 16) & 0xffffffff
    return lo <= a <= hi

print("\n=== block a32cb80..a32cc40 (what leads into the slice checks) ===")
for l in lines:
    if in_range(l, 0xa32cb80, 0xa32cc40):
        print(l.strip())

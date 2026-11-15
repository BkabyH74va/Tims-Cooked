#!/usr/bin/env python3
B = open("/Users/USER/iosurface-kext/com.apple.iokit.IOSurface","rb").read()
def dump(off, n=160):
    chunk = B[off:off+n]
    out = []
    for s in chunk.split(b"\0"):
        if s: out.append(s.decode("utf-8","replace"))
    return out

print("=== cstring around 0x1880..0x1a60 (file offsets) ===")
for o in range(0x1880, 0x1a60, 0x20):
    for s in dump(o, 0x20):
        if len(s) > 4:
            print(f"  0x{o:x}: {s!r}")

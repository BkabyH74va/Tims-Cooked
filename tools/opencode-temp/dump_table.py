#!/usr/bin/env python3
import struct
B = open("/Users/USER/iosurface-kext/com.apple.iokit.IOSurface","rb").read()

def dump(lo, hi, step=4):
    for off in range(lo, hi, step):
        if off+4 > len(B): break
        v = struct.unpack_from("<I", B, off)[0]
        print(f"  0x{off:06x}: 0x{v:08x}  {v}")

print("=== 0x46600..0x467a0 as u32 ===")
dump(0x46600, 0x467a0)

print("\n=== 0x46b40..0x46bd0 as u32 ===")
dump(0x46b40, 0x46bd0)

print("\n=== section map ===")
# LC_SEGMENT_64 sections
ncmds = struct.unpack_from("<I", B, 16)[0]
off = 32
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", B, off)
    if cmd == 0x19:  # LC_SEGMENT_64
        segname = B[off+8:off+24].rstrip(b"\0").decode()
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", B, off+24)
        nsects = struct.unpack_from("<I", B, off+64)[0]
        so = off + 72
        for _ in range(nsects):
            sect = B[so:so+16].rstrip(b"\0").decode()
            addr, size = struct.unpack_from("<QQ", B, so+32)
            soff = struct.unpack_from("<I", B, so+48)[0]
            if 0x46000 <= soff <= 0x48000:
                print(f"  {segname}.{sect} addr=0x{addr:x} off=0x{soff:x} size=0x{size:x}")
            so += 80
    off += cmdsize

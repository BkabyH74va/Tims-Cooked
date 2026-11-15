#!/usr/bin/env python3
"""Debug Mach-O parsing of kernelcache."""
import struct
from pathlib import Path

KC = Path("G:/REPO/firmware/24A446/kernelcache.release.macho")

data = KC.read_bytes()
magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from(
    "<IiiIIIII", data, 0
)
print(f"magic={magic:#x} ncmds={ncmds} sizeofcmds={sizeofcmds}")

off = 32
total_sections = 0
for i in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == 0x19:
        segname = data[off + 8:off + 24].rstrip(b"\0").decode("ascii", "replace")
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
        maxprot, initprot, nsects, flag = struct.unpack_from("<IIII", data, off + 56)
        print(f"\nSegment {i}: {segname}")
        print(f"  vmaddr={vmaddr:#018x} vmsize={vmsize:#x} fileoff={fileoff:#x} filesize={filesize:#x}")
        print(f"  nsects={nsects} cmdsize={cmdsize}")
        
        so = off + 72
        for j in range(nsects):
            if so + 80 > len(data):
                print(f"  Section {j}: OUT OF BOUNDS at {so:#x}")
                break
            sectname = data[so:so + 16].rstrip(b"\0").decode("ascii", "replace")
            seg = data[so + 16:so + 32].rstrip(b"\0").decode("ascii", "replace")
            addr, size = struct.unpack_from("<QQ", data, so + 32)
            offset, align = struct.unpack_from("<II", data, so + 48)
            print(f"  Section {j}: {seg}.{sectname} va={addr:#018x} size={size:#x} off={offset:#x}")
            total_sections += 1
            so += 80
    off += cmdsize

print(f"\nTotal sections found: {total_sections}")

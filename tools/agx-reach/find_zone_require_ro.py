#!/usr/bin/env python3
"""Find the VA of _zone_require_ro string in the kernel."""
import struct
from pathlib import Path

KC = Path('G:/REPO/tools/agx-reach/kernel_analysis/kexts/com.apple.kernel')
data = KC.read_bytes()

magic, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, 0)
assert magic == 0xFEEDFACF

# Parse segments and sections
segments = []
sections = []
off = 32
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == 0x19:  # LC_SEGMENT_64
        segname = data[off + 8:off + 24].rstrip(b"\0").decode()
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
        segments.append({"name": segname, "vmaddr": vmaddr, "vmsize": vmsize, "fileoff": fileoff, "filesize": filesize})
        so = off + 72
        nsects = struct.unpack_from("<I", data, off + 64)[0]
        for _ in range(nsects):
            sectname = data[so:so + 16].rstrip(b"\0").decode()
            seg = data[so + 16:so + 32].rstrip(b"\0").decode()
            addr, size = struct.unpack_from("<QQ", data, so + 32)
            offset = struct.unpack_from("<I", data, so + 48)[0]
            sections.append({"seg": seg, "sect": sectname, "addr": addr, "size": size, "offset": offset})
            so += 80
    off += cmdsize

# Find which section contains file offset 0xc5ca31
target_foff = 0xc5ca31
for s in sections:
    if s["offset"] <= target_foff < s["offset"] + s["size"]:
        va = s["addr"] + (target_foff - s["offset"])
        print(f"_zone_require_ro string at file offset {target_foff:#x}")
        print(f"  Section: {s['seg']}.{s['sect']}")
        print(f"  Section VA: {s['addr']:#018x}, size: {s['size']:#x}, file offset: {s['offset']:#x}")
        print(f"  String VA: {va:#018x}")
        break

# Also find all sections in __TEXT
print(f"\n=== __TEXT sections ===")
for s in sections:
    if s["seg"] == "__TEXT":
        print(f"  {s['sect']}: va={s['addr']:#018x} size={s['size']:#x} offset={s['offset']:#x}")

# Find which sections contain strings like "zone_require_ro failed"
print(f"\n=== Searching for zone_require_ro failed strings ===")
for pattern in [b'zone_require_ro failed', b'_zone_require_ro', b'zone_require']:
    idx = data.find(pattern)
    while idx != -1:
        # Find which section contains this offset
        for s in sections:
            if s["offset"] <= idx < s["offset"] + s["size"]:
                va = s["addr"] + (idx - s["offset"])
                print(f"  '{pattern.decode()}' at file offset {idx:#x}, VA {va:#018x} ({s['seg']}.{s['sect']})")
                break
        idx = data.find(pattern, idx + 1)

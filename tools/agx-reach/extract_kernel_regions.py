#!/usr/bin/env python3
"""Extract text regions from kernelcache for analysis."""
import struct
from pathlib import Path

KC = Path("G:/REPO/firmware/24A446/kernelcache.release.macho")
OUT_DIR = Path("G:/REPO/tools/agx-reach/kernel_analysis")
OUT_DIR.mkdir(parents=True, exist_ok=True)

data = KC.read_bytes()
magic, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, 0)
assert magic == 0xFEEDFACF

off = 32
regions = []
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == 0x19:
        segname = data[off + 8:off + 24].rstrip(b"\0").decode()
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
        nsects = struct.unpack_from("<I", data, off + 64)[0]
        if nsects > 0:
            so = off + 72
            for _ in range(nsects):
                sectname = data[so:so + 16].rstrip(b"\0").decode()
                seg = data[so + 16:so + 32].rstrip(b"\0").decode()
                addr, size = struct.unpack_from("<QQ", data, so + 32)
                offset = struct.unpack_from("<I", data, so + 48)[0]
                if "text" in sectname.lower() or segname == "__TEXT_EXEC":
                    regions.append({
                        "name": f"{segname}.{sectname}",
                        "va": addr, "size": size, "off": offset,
                    })
                    print(f"  {seg}.{sectname}: va={addr:#018x} size={size:#x} off={offset:#x}")
                so += 80
        else:
            # Segment with no named sections - dump whole thing if it's executable
            prot = ""
            maxprot, initprot = struct.unpack_from("<II", data, off + 56)
            if initprot & 4:  # executable
                regions.append({
                    "name": segname,
                    "va": vmaddr, "size": vmsize, "off": fileoff,
                })
                print(f"  {segname} (exec, no sections): va={vmaddr:#018x} size={vmsize:#x} off={fileoff:#x}")
    off += cmdsize

# Extract each region
for r in regions:
    out = OUT_DIR / f"{r['name'].replace('.', '_')}.bin"
    chunk = data[r["off"]:r["off"] + r["size"]]
    out.write_bytes(chunk)
    print(f"Wrote {out} ({len(chunk):,} bytes)")

# Also save a combined text blob for searching
all_text = b""
for r in regions:
    chunk = data[r["off"]:r["off"] + r["size"]]
    all_text += chunk

combined = OUT_DIR / "all_exec.bin"
combined.write_bytes(all_text)
print(f"\nCombined exec: {combined} ({len(all_text):,} bytes)")
print(f"Output dir: {OUT_DIR}")

#!/usr/bin/env python3
"""Examine raw bytes of LC_FILESET_ENTRY (0x80000035) commands."""
import struct
from pathlib import Path

KC = Path("G:/REPO/firmware/24A446/kernelcache.release.macho")

data = KC.read_bytes()
LC_FILESET_ENTRY = 0x80000035

off = 32
count = 0
for i in range(314):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == LC_FILESET_ENTRY:
        print(f"\n=== LC_FILESET_ENTRY #{count} at file off {off:#x} ===")
        print(f"  cmdsize={cmdsize}")
        # Print raw bytes as hex
        hex_str = " ".join(f"{b:02x}" for b in data[off:off+min(cmdsize, 64)])
        print(f"  Raw bytes: {hex_str}")
        
        # Try to parse as different structures
        # Try: cmd, cmdsize, entry_id(4), offset(8), name...
        if cmdsize >= 20:
            val8 = struct.unpack_from("<Q", data, off + 8)[0]
            val12 = struct.unpack_from("<Q", data, off + 12)[0]
            val16 = struct.unpack_from("<Q", data, off + 16)[0]
            print(f"  Bytes 8-15: {val8:#018x}")
            print(f"  Bytes 12-19: {val12:#018x}")
            print(f"  Bytes 16-23: {val16:#018x}")
            
            # The offset might be at bytes 8-15 (entry_id?) or 12-19
            # Let's check if either looks like a file offset (< 78MB)
            if val8 < len(data):
                print(f"  Bytes 8-15 looks like file offset: {val8:#x}")
            if val12 < len(data):
                print(f"  Bytes 12-19 looks like file offset: {val12:#x}")
            if val16 < len(data):
                print(f"  Bytes 16-23 looks like file offset: {val16:#x}")
        
        count += 1
        if count >= 5:
            break
    off += cmdsize

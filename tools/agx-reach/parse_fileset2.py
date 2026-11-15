#!/usr/bin/env python3
"""Parse LC_FILESET_ENTRY commands (0x80000035) from kernelcache."""
import struct
from pathlib import Path

KC = Path("G:/REPO/firmware/24A446/kernelcache.release.macho")

data = KC.read_bytes()
magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from(
    "<IiiIIIII", data, 0
)

# LC_FILESET_ENTRY command type in this kernelcache
LC_FILESET_ENTRY = 0x80000035

off = 32
entries = []
for i in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == LC_FILESET_ENTRY:
        # Parse the fileset entry structure
        # Based on XNU source, this might be:
        # struct {
        #   uint32_t cmd;
        #   uint32_t cmdsize;
        #   uint32_t entry_id;
        #   uint64_t offset;  // file offset to embedded Mach-O
        #   char name[];      // null-terminated name string
        # }
        
        if cmdsize >= 20:
            entry_id = struct.unpack_from("<I", data, off + 8)[0]
            entry_offset = struct.unpack_from("<Q", data, off + 12)[0]
            # Read name string
            name_off = off + 20
            name_end = data.index(b"\x00", name_off) if b"\x00" in data[name_off:name_off+256] else name_off + 256
            entry_name = data[name_off:name_end].decode("ascii", "replace")
        else:
            entry_id = 0
            entry_offset = 0
            entry_name = f"unknown_{i}"
        
        entries.append({
            "index": len(entries),
            "entry_id": entry_id,
            "entry_offset": entry_offset,
            "name": entry_name,
            "cmd_off": off,
            "cmdsize": cmdsize,
        })
    off += cmdsize

print(f"Found {len(entries)} fileset entries (LC_FILESET_ENTRY 0x80000035)")
print()

# Verify each entry points to a valid Mach-O
for entry in entries[:10]:
    entry_off = entry["entry_offset"]
    if entry_off < len(data):
        entry_magic = struct.unpack_from("<I", data, entry_off)[0]
        is_macho = entry_magic in (0xFEEDFACF, 0xFEEDFACE, 0xCAFEBABE, 0xCFFAEDFE)
        print(f"  Entry {entry['index']}: name='{entry['name']}' offset={entry_off:#x} magic={entry_magic:#x} {'MACH-O' if is_macho else 'NOT MACHO'}")
    else:
        print(f"  Entry {entry['index']}: name='{entry['name']}' offset={entry_off:#x} OUT OF RANGE")

print(f"\n... showing first 10 of {len(entries)} entries")

# Now try to extract the main kernel entry (the first one or the one with kernel code)
# The first embedded Mach-O should be the main kernel
if entries:
    first_entry = entries[0]
    entry_off = first_entry["entry_offset"]
    entry_magic = struct.unpack_from("<I", data, entry_off)[0]
    if entry_magic == 0xFEEDFACF:
        print(f"\nFirst entry is a valid 64-bit Mach-O at offset {entry_off:#x}")
        # Parse its load commands to find segments
        eoff = entry_off + 32
        _, _, _, _, entry_ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, entry_off)
        print(f"  Ncmds: {entry_ncmds}")
        for j in range(min(entry_ncmds, 20)):
            ecmd, ecmdsize = struct.unpack_from("<II", data, eoff)
            if ecmd == 0x19:  # LC_SEGMENT_64
                segname = data[eoff + 8:eoff + 24].rstrip(b"\0").decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, eoff + 24)
                print(f"    Segment: {segname} va={vmaddr:#018x} size={vmsize:#x} foff={fileoff:#x}")
            eoff += ecmdsize

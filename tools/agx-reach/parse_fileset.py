#!/usr/bin/env python3
"""Parse iOS 27.0.1 kernelcache MH_FILESET to extract individual Mach-O entries."""
import struct
from pathlib import Path

KC = Path("G:/REPO/firmware/24A446/kernelcache.release.macho")
OUT_DIR = Path("G:/REPO/tools/agx-reach/kernel_analysis/filesets")
OUT_DIR.mkdir(parents=True, exist_ok=True)

data = KC.read_bytes()
magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from(
    "<IiiIIIII", data, 0
)

print(f"Magic: {magic:#x} ({'MH_FILESET' if magic == 0xFEEDFACE else 'MH_MAGIC_64' if magic == 0xFEEDFACF else 'OTHER'})")
print(f"Filetype: {filetype} ({'MH_FILESET' if filetype == 9 else 'OTHER'})")
print(f"Ncmds: {ncmds}, Sizeofcmds: {sizeofcmds}")
print()

off = 32
entries = []
for i in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == 0x24:  # LC_FILESET_ENTRY
        # LC_FILESET_ENTRY structure:
        # cmd (4), cmdsize (4), entry_id (4), ... then data
        # Actually let me look at the proper structure
        entry_id = struct.unpack_from("<I", data, off + 8)[0]
        # The entry data follows the cmd header
        # LC_FILESET_ENTRY: cmd, cmdsize, entry_id (uint32), then data
        # The entry data is: offset (uint64) to the embedded Mach-O
        # Wait, let me check the actual structure
        
        # In XNU, LC_FILESET_ENTRY contains:
        # struct fileset_entry_command {
        #   uint32_t cmd;        // LC_FILESET_ENTRY
        #   uint32_t cmdsize;    // sizeof(struct fileset_entry_command)
        #   uint32_t entry_id;   // unique ID
        #   uint64_t offset;     // file offset to embedded Mach-O
        # } followed by a string (name)
        
        entry_offset = struct.unpack_from("<Q", data, off + 12)[0]
        # Read name (null-terminated string after the fixed header)
        name_off = off + 20
        name_end = data.index(b"\x00", name_off) if b"\x00" in data[name_off:name_off+256] else name_off + 256
        entry_name = data[name_off:name_end].decode("ascii", "replace")
        
        entries.append({
            "index": i,
            "entry_id": entry_id,
            "entry_offset": entry_offset,
            "name": entry_name,
            "cmd_off": off,
            "cmdsize": cmdsize,
        })
        print(f"  Entry {i}: id={entry_id} name='{entry_name}' offset={entry_offset:#x} ({entry_offset:,})")
    off += cmdsize

print(f"\nTotal fileset entries: {len(entries)}")

# Now extract each entry's embedded Mach-O
for entry in entries:
    entry_off = entry["entry_offset"]
    entry_magic = struct.unpack_from("<I", data, entry_off)[0]
    if entry_magic == 0xFEEDFACF:  # MH_MAGIC_64
        # Parse this embedded Mach-O
        entry_data_start = entry_off
        _, _, _, _, entry_ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, entry_off)
        
        # Find __TEXT_EXEC segment
        eoff = entry_off + 32
        for j in range(entry_ncmds):
            ecmd, ecmdsize = struct.unpack_from("<II", data, eoff)
            if ecmd == 0x19:  # LC_SEGMENT_64
                segname = data[eoff + 8:eoff + 24].rstrip(b"\0").decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, eoff + 24)
                if "TEXT_EXEC" in segname or segname == "__TEXT_EXEC":
                    print(f"\n  Entry '{entry_name}': __TEXT_EXEC at va={vmaddr:#018x} size={vmsize:#x} foff={fileoff:#x}")
                    # Extract the text
                    text_data = data[entry_off + fileoff:entry_off + fileoff + filesize]
                    out_file = OUT_DIR / f"{entry_name.replace('/', '_')}_text.bin"
                    out_file.write_bytes(text_data)
                    print(f"    Extracted {len(text_data):,} bytes to {out_file}")
                elif segname == "__TEXT":
                    print(f"\n  Entry '{entry_name}': __TEXT at va={vmaddr:#018x} size={vmsize:#x} foff={fileoff:#x}")
            eoff += ecmdsize
    elif entry_magic == 0xCAFEBABE or entry_magic == 0xFEEDFACE:
        print(f"  Entry '{entry_name}': 32-bit Mach-O (magic={entry_magic:#x}), skipping")
    else:
        print(f"  Entry '{entry_name}': unknown magic {entry_magic:#x} at offset {entry_off:#x}")

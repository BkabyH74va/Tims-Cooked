#!/usr/bin/env python3
"""Extract individual fileset entries from kernelcache."""
import struct
from pathlib import Path

KC = Path("G:/REPO/firmware/24A446/kernelcache.release.macho")
OUT_DIR = Path("G:/REPO/tools/agx-reach/kernel_analysis/filesets")
OUT_DIR.mkdir(parents=True, exist_ok=True)

data = KC.read_bytes()
LC_FILESET_ENTRY = 0x80000035

off = 32
entries = []
for i in range(314):  # ncmds
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == LC_FILESET_ENTRY:
        # Structure:
        # cmd (4), cmdsize (4), va_offset (8), file_offset (8), entry_id (4), pad(4), name(null-terminated)
        va_offset = struct.unpack_from("<Q", data, off + 8)[0]
        file_offset = struct.unpack_from("<Q", data, off + 16)[0]
        entry_id = struct.unpack_from("<I", data, off + 24)[0]
        name_off = off + 28
        name_end = data.index(b"\x00", name_off) if b"\x00" in data[name_off:name_off+256] else name_off + 256
        entry_name = data[name_off:name_end].decode("ascii", "replace")
        
        entries.append({
            "index": i,
            "entry_id": entry_id,
            "va_offset": va_offset,
            "file_offset": file_offset,
            "name": entry_name,
        })
    off += cmdsize

print(f"Found {len(entries)} fileset entries")
print()

# Extract each entry's embedded Mach-O
for entry in entries:
    foff = entry["file_offset"]
    if foff >= len(data):
        continue
    
    # Check if it's a valid Mach-O
    entry_magic = struct.unpack_from("<I", data, foff)[0]
    if entry_magic == 0xFEEDFACF:  # MH_MAGIC_64
        # Parse embedded Mach-O to find its size
        _, _, _, _, entry_ncmds, entry_sizeofcmds, _, _ = struct.unpack_from("<IiiIIIII", data, foff)
        
        # Find end of load commands to get the full size
        eoff = foff + 32
        max_end = foff
        for j in range(entry_ncmds):
            if eoff + 8 > len(data):
                break
            ecmd, ecmdsize = struct.unpack_from("<II", data, eoff)
            if ecmd == 0x19:  # LC_SEGMENT_64
                seg_filesize = struct.unpack_from("<Q", data, eoff + 40)[0]
                seg_fileoff = struct.unpack_from("<Q", data, eoff + 32)[0]
                seg_end = seg_fileoff + seg_filesize
                if seg_end > max_end:
                    max_end = seg_end
            eoff += ecmdsize
        
        entry_size = max_end - foff
        entry_data = data[foff:foff + entry_size]
        
        # Check if it has __TEXT_EXEC segment
        has_text_exec = False
        eoff = foff + 32
        for j in range(entry_ncmds):
            if eoff + 72 > len(data):
                break
            ecmd, ecmdsize = struct.unpack_from("<II", data, eoff)
            if ecmd == 0x19:
                segname = data[eoff + 8:eoff + 24].rstrip(b"\0").decode()
                if segname == "__TEXT_EXEC":
                    has_text_exec = True
                    break
            eoff += ecmdsize
        
        safe_name = entry_name.replace("/", "_").replace(".", "_")
        out_file = OUT_DIR / f"{safe_name}.macho"
        out_file.write_bytes(entry_data)
        
        text_exec_mark = " [TEXT_EXEC]" if has_text_exec else ""
        print(f"  [{entry['index']:3d}] {entry_name:<40s} va={entry['va_offset']:#018x} foff={entry['file_offset']:#x} size={entry_size:>8,} {text_exec_mark}")
    else:
        print(f"  [{entry['index']:3d}] {entry_name:<40s} foff={entry['file_offset']:#x} magic={entry_magic:#x} (not Mach-O)")

print(f"\nExtracted entries to {OUT_DIR}")

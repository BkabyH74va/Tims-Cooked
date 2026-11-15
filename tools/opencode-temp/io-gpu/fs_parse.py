#!/usr/bin/env python3
"""Independent parser for the kernelcache fileset: locate com.apple.iokit.IOGPUFamily.

Gotchas handled (per task brief):
  LC_FILESET_ENTRY = 0x80000035
    cmd(4) cmdsize(4) vmaddr(u64 @+8) fileoff(u64 @+16) entry_id(u32 @+24) reserved(u32 @+28)
    NUL-terminated NAME at +32
  Members are PRELINKED: LC_SEGMENT_64 fileoff is at +40, filesize at +48, and they are
  ABSOLUTE offsets into the kernelcache (not relative to the member's start).
"""
import struct
import sys
from pathlib import Path

KC = Path(r"G:/REPO\firmware\24A446\kernelcache.release.macho")
LC_FILESET_ENTRY = 0x80000035
LC_SEGMENT_64 = 0x19

TARGET = "com.apple.iokit.IOGPUFamily"


def main():
    data = KC.read_bytes()
    magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, _ = struct.unpack_from(
        "<IiiIIIII", data, 0
    )
    print(f"kernelcache magic={magic:#x} filetype={filetype} ncmds={ncmds} sizeofcmds={sizeofcmds:#x}")
    print(f"file size={len(data):#x} ({len(data):,})")

    off = 32
    entries = []
    for i in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_FILESET_ENTRY:
            vmaddr, fileoff = struct.unpack_from("<QQ", data, off + 8)
            entry_id, reserved = struct.unpack_from("<II", data, off + 24)
            noff = off + 32
            nend = data.index(b"\0", noff)
            name = data[noff:nend].decode("ascii", "replace")
            entries.append((i, name, vmaddr, fileoff, entry_id, off, cmdsize))
        off += cmdsize

    print(f"\nfileset entries: {len(entries)}")
    for (i, name, vmaddr, fileoff, eid, coff, cs) in entries:
        if TARGET in name:
            print(f"\n=== {name} ===")
            print(f"  cmd index     : {i}")
            print(f"  entry_id      : {eid}")
            print(f"  vmaddr        : {vmaddr:#018x}")
            print(f"  fileoff       : {fileoff:#x} ({fileoff:,})")
            print(f"  cmdoff        : {coff:#x} cmdsize={cs:#x}")
            print(f"  magic at foff : {struct.unpack_from('<I', data, fileoff)[0]:#x}")
            emagic, ecpu, esub, eftyp, encmds, eszcmds, eflags, _ = struct.unpack_from(
                "<IiiIIIII", data, fileoff
            )
            print(f"  member header : cputype={ecpu} filetype={eftyp} ncmds={encmds} sizeofcmds={eszcmds:#x} flags={eflags:#x}")

            eoff = fileoff + 32
            end = fileoff
            segs = []
            for j in range(encmds):
                ecmd, ecmdsize = struct.unpack_from("<II", data, eoff)
                if ecmd == LC_SEGMENT_64:
                    segname = data[eoff + 8:eoff + 24].rstrip(b"\0").decode("ascii", "replace")
                    s_vmaddr, s_vmsize, s_fileoff, s_filesize = struct.unpack_from("<QQQQ", data, eoff + 24)
                    nsects = struct.unpack_from("<I", data, eoff + 64)[0]
                    segs.append((segname, s_vmaddr, s_vmsize, s_fileoff, s_filesize, nsects, eoff))
                    print(
                        f"    SEG {segname:<14s} vmaddr={s_vmaddr:#018x} vmsize={s_vmsize:#x} "
                        f"fileoff={s_fileoff:#x} filesize={s_filesize:#x} nsects={nsects}"
                    )
                    so = eoff + 72
                    for _ in range(nsects):
                        sectname = data[so:so + 16].rstrip(b"\0").decode("ascii", "replace")
                        seg = data[so + 16:so + 32].rstrip(b"\0").decode("ascii", "replace")
                        saddr, ssize = struct.unpack_from("<QQ", data, so + 32)
                        soff = struct.unpack_from("<I", data, so + 48)[0]
                        print(
                            f"       {seg:<14s}.{sectname:<20s} addr={saddr:#018x} size={ssize:#x} off={soff:#x}"
                        )
                        so += 80
                    seg_end = s_fileoff + s_filesize
                    if seg_end > end:
                        end = seg_end
                else:
                    print(f"    LC cmd {ecmd:#x} cmdsize={ecmdsize:#x}")
                eoff += ecmdsize
            print(f"  computed member size = {end - fileoff:#x} ({end-fileoff:,})")

            # dump to scratch
            out = Path(r"G:/REPO\tools\opencode-temp\io-gpu\member.macho")
            out.write_bytes(data[fileoff:end])
            print(f"  wrote {out} sha256 pending")

    # also show a couple of neighbouring entries for context
    print("\nfirst 5 entries:")
    for e in entries[:5]:
        print(f"   {e[1]}")


if __name__ == "__main__":
    main()

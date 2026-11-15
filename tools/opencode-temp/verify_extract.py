#!/usr/bin/env python3
"""Verify that the ipsw-extracted kexts are byte-identical to the prelinked
fileset members inside the 27.0.1 kernelcache, and report the fileset entry
metadata for both."""
import hashlib
import struct
import sys

sys.path.insert(0, r"G:/REPO\tools\opencode-temp")
from kc import KC, IOSURFACE, IOMGF, parse_fileset, macho_segments, macho_sections

kc = KC.read_bytes()
entries, filetype = parse_fileset(kc)
print(f"kernelcache filetype={filetype} entries={len(entries)}")
print()

for target, path in (("com.apple.iokit.IOSurface", IOSURFACE),
                     ("com.apple.iokit.IOMobileGraphicsFamily", IOMGF)):
    hit = [e for e in entries if e[0] == target]
    assert len(hit) == 1, hit
    name, vmaddr, fileoff, entry_id, cmd_off = hit[0]
    print("=" * 78)
    print(f"{name}")
    print(f"  fileset cmd offset : {cmd_off:#x}")
    print(f"  fileset vmaddr     : {vmaddr:#018x}")
    print(f"  fileset fileoff    : {fileoff:#x}")
    print(f"  fileset entry_id   : {entry_id}")
    raw = kc[cmd_off:cmd_off + 40]
    print(f"  entry bytes [+0..39]: {raw.hex(' ')}")
    print(f"  name bytes [+32..] : {kc[cmd_off+32:cmd_off+32+len(name)+1].hex(' ')}")

    # embedded mach-o header at fileoff
    magic = struct.unpack_from("<I", kc, fileoff)[0]
    print(f"  embedded magic     : {magic:#x}")
    segs = macho_segments(kc, fileoff)
    print("  prelinked segments (file offsets are ABSOLUTE into kernelcache):")
    for sname, sva, svmsz, sfoff, sfsz in segs:
        print(f"    {sname:16s} va={sva:#018x} vmsz={svmsz:#x} "
              f"fileoff={sfoff:#x} filesize={sfsz:#x}")

    # Now compare with the standalone extraction.
    ex = path.read_bytes()
    esecs = macho_sections(ex)
    print("  extracted file segments:")
    total_match = True
    for seg, sect, addr, size, off in esecs:
        # find the matching prelinked segment/section
        match = None
        for sname, sva, svmsz, sfoff, sfsz in segs:
            if sname != seg:
                continue
            for s2, s3, s4, s5, s6 in macho_sections(kc, fileoff):
                if s2 == seg and s3 == sect:
                    match = (s4, s5, s6)
                    break
        if match is None:
            continue
        m_addr, m_size, m_off = match
        if m_size == 0 or size == 0:
            continue
        a = ex[off:off + size]
        b = kc[m_off:m_off + m_size]
        same = a == b
        if not same:
            total_match = False
        print(f"    {seg}.{sect:22s} va={addr:#018x} size={size:#x} "
              f"kc_off={m_off:#x} identical={same}")
    print(f"  ALL SECTION BYTES IDENTICAL: {total_match}")
    print(f"  extracted file sha256: {hashlib.sha256(ex).hexdigest()}")
    print(f"  extracted file size  : {len(ex)}")
    print()

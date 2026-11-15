#!/usr/bin/env python3
"""f1iogpu: verify ipsw's extracted IOGPUFamily member is byte-faithful to the kernelcache.

The kernelcache member is PRELINKED and NON-CONTIGUOUS: each LC_SEGMENT_64's
fileoff/filesize are ABSOLUTE into the kernelcache (fileoff @ +40, filesize @ +48).
ipsw re-materialises the member into a contiguous standalone Mach-O with the same
vmaddrs but new file offsets. Verify every section's bytes match.
"""
import hashlib
import struct
from pathlib import Path

KC = Path(r"G:/REPO\firmware\24A446\kernelcache.release.macho")
EXT = Path(r"G:/REPO\tools\opencode-temp\io-gpu\com.apple.iokit.IOGPUFamily")
LC_SEGMENT_64 = 0x19
LC_FILESET_ENTRY = 0x80000035
TARGET = "com.apple.iokit.IOGPUFamily"

kc = KC.read_bytes()
ext = EXT.read_bytes()

off = 32
_, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", kc, 0)
target = None
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", kc, off)
    if cmd == LC_FILESET_ENTRY:
        noff = off + 32
        name = kc[noff:kc.index(b"\0", noff)].decode("ascii", "replace")
        if name == TARGET:
            target = (struct.unpack_from("<Q", kc, off + 16)[0], struct.unpack_from("<Q", kc, off + 8)[0])
    off += cmdsize
member_foff, member_vmaddr = target
print(f"member fileoff={member_foff:#x} vmaddr={member_vmaddr:#018x}")

_, _, _, _, mncmds, _, _, _ = struct.unpack_from("<IiiIIIII", kc, member_foff)
moff = member_foff + 32
kc_sections = []
for _ in range(mncmds):
    cmd, cmdsize = struct.unpack_from("<II", kc, moff)
    if cmd == LC_SEGMENT_64:
        nsects = struct.unpack_from("<I", kc, moff + 64)[0]
        so = moff + 72
        for _ in range(nsects):
            sectname = kc[so:so + 16].rstrip(b"\0").decode("ascii", "replace")
            seg = kc[so + 16:so + 32].rstrip(b"\0").decode("ascii", "replace")
            saddr, ssize = struct.unpack_from("<QQ", kc, so + 32)
            soff = struct.unpack_from("<I", kc, so + 48)[0]
            kc_sections.append((seg, sectname, saddr, ssize, soff))
            so += 80
    moff += cmdsize

_, _, _, _, encmds, _, _, _ = struct.unpack_from("<IiiIIIII", ext, 0)
eoff = 32
ext_sections = []
for _ in range(encmds):
    cmd, cmdsize = struct.unpack_from("<II", ext, eoff)
    if cmd == LC_SEGMENT_64:
        nsects = struct.unpack_from("<I", ext, eoff + 64)[0]
        so = eoff + 72
        for _ in range(nsects):
            sectname = ext[so:so + 16].rstrip(b"\0").decode("ascii", "replace")
            seg = ext[so + 16:so + 32].rstrip(b"\0").decode("ascii", "replace")
            saddr, ssize = struct.unpack_from("<QQ", ext, so + 32)
            soff = struct.unpack_from("<I", ext, so + 48)[0]
            ext_sections.append((seg, sectname, saddr, ssize, soff))
            so += 80
    eoff += cmdsize

ext_map = {(s[0], s[1]): s for s in ext_sections}
allok = True
for seg, sect, addr, size, koff in kc_sections:
    e = ext_map.get((seg, sect))
    if e is None:
        print(f"  {seg}.{sect}: MISSING in extract")
        allok = False
        continue
    _, _, eaddr, esize, eoff2 = e
    if size == 0:
        print(f"  {seg}.{sect:<22s} (zero-size)")
        continue
    kb = kc[koff:koff + size]
    eb = ext[eoff2:eoff2 + size]
    ok = kb == eb and addr == eaddr
    allok &= ok
    print(
        f"  {seg}.{sect:<22s} kc_off={koff:#010x} ext_off={eoff2:#08x} size={size:#x} "
        f"addr_match={addr==eaddr} bytes_match={kb==eb} sha={hashlib.sha256(kb).hexdigest()[:16]}"
    )
print("ALL NONZERO SECTIONS MATCH" if allok else "MISMATCH")
print(f"extracted file sha256: {hashlib.sha256(ext).hexdigest()}")
print(f"extracted file size  : {len(ext)}")

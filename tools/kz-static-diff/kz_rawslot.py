#!/usr/bin/env python3
"""Raw arm64e pointer-slot finder for one fileset member.

The chained-fixup decoders miss arm64e *auth* pointer tables: those store a full
64-bit value whose low 32 bits are the target minus the member's __TEXT vmaddr
(measured on iOS 27: TEXT_VMADDR 0xfffffe0007004000), with the PAC in the high
bits. A raw aligned quadword scan over every segment finds them, and controls
prove whether an empty result means "unreferenced" or "decoder missed it".

Usage: python kz_rawslot.py <build> <member> <hex-va> [more-vas...]
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))
from kc_member import load_member  # noqa: E402

TEXT_VMADDR = 0xFFFFFE0007004000


def main(argv):
    if len(argv) < 4:
        raise SystemExit(__doc__)
    bld, member = argv[1], argv[2]
    targets = {int(a, 16): [] for a in argv[3:]}
    b = load_member(bld, member)
    offs = {t: (t - TEXT_VMADDR) & 0xFFFFFFFF for t in targets}
    for nm, (vm, vsz, fo, fsz) in sorted(b["segs"].items(), key=lambda x: x[1][0]):
        blob = b["data"][fo:fo + fsz]
        for i in range(0, len(blob) - 7, 8):
            w = struct.unpack_from("<Q", blob, i)[0]
            lo = w & 0xFFFFFFFF
            for t, o in offs.items():
                if lo == o:
                    targets[t].append((nm, vm + i, w))
    for t in targets:
        print("%s %s -> %#x : %d slot(s)" % (bld, member, t, len(targets[t])))
        for nm, va, w in targets[t][:20]:
            print("   [%s] %#x  0x%016x" % (nm, va, w))


if __name__ == "__main__":
    main(sys.argv)

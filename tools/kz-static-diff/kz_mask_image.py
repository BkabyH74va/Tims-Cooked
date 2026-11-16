#!/usr/bin/env python3
"""Count `and ...,#0xfffffffffffffeff` sites across an entire kernelcache image.

Single pass over `__PRELINK_TEXT` + `__TEXT_EXEC` (all fileset members at once),
so the scope of the 27.2 bit-8-clearing idiom can be measured image-wide instead
of member by member.

Usage:
    python kz_mask_image.py <build>
"""
import struct
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))
import capstone  # noqa: E402
from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402
from capstone.arm64 import ARM64_OP_IMM  # noqa: E402

MASK = 0xFFFFFFFFFFFFFEFF


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    bld = argv[1]
    d = (ROOT / "firmware" / bld / "kernelcache.release.macho").read_bytes()
    ncmds = struct.unpack_from("<I", d, 16)[0]
    off = 32
    segs = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", d, off)
        if cmd == 0x19:
            nm = d[off + 8:off + 24].rstrip(b"\0").decode(errors="replace")
            vm, vsz, fo, fsz = struct.unpack_from("<QQQQ", d, off + 24)
            segs.append((nm, vm, vsz, fo, fsz))
        off += cmdsize
    md = capstone.Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True
    total = 0
    per_seg = Counter()
    for nm, vm, vsz, fo, fsz in segs:
        # note: "__PRELINK_TEXT" does not contain the substring "__TEXT"
        if "TEXT" not in nm or nm.startswith("__DATA"):
            continue
        blob = d[fo:fo + fsz]
        n = 0
        for ins in md.disasm(blob, vm):
            if ins.mnemonic != "and":
                continue
            ops = ins.operands
            if len(ops) >= 3 and ops[-1].type == ARM64_OP_IMM and \
                    (ops[-1].imm & ((1 << 64) - 1)) == MASK:
                n += 1
        per_seg[nm] = n
        total += n
    print("%s: %d sites of and #~0x100" % (bld, total))
    for nm, n in per_seg.items():
        print("   %-20s %d" % (nm, n))


if __name__ == "__main__":
    main(sys.argv)

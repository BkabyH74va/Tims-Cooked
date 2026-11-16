#!/usr/bin/env python3
"""Count instructions that test/set bit 8 (0x100) across a whole kernelcache.

Companion to `kz_mask_image.py`: if 27.2 not only clears bit 8 but also starts
testing it in the same thunks, the bit is a meaningful state flag; if nothing
tests it, the clear is more likely a hygiene/stale-state operation.

Usage:
    python kz_bit8_image.py <build>
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
    c = Counter()
    for nm, vm, vsz, fo, fsz in segs:
        if "TEXT" not in nm or nm.startswith("__DATA"):
            continue
        for ins in md.disasm(d[fo:fo + fsz], vm):
            m = ins.mnemonic
            try:
                ops = ins.operands
            except capstone.CsError:
                continue
            if not ops or ops[-1].type != ARM64_OP_IMM:
                continue
            imm = ops[-1].imm & ((1 << 64) - 1)
            if m in ("tbz", "tbnz") and imm == 8:
                c["%s #%d" % (m, imm)] += 1
            elif m in ("tst", "ands") and imm == 0x100:
                c["%s #0x100" % m] += 1
            elif m in ("orr", "orrs") and imm == 0x100:
                c["%s #0x100" % m] += 1
            elif m in ("bics", "bic") and imm == 0x100:
                c["%s #0x100" % m] += 1
    print("%s:" % bld)
    for k, v in sorted(c.items()):
        print("   %-16s %d" % (k, v))


if __name__ == "__main__":
    main(sys.argv)

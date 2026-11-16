#!/usr/bin/env python3
"""Linear-sweep a kernelcache build and report every direct BL/B to a target VA.

Finds *direct* callers only; virtual dispatches (ldr slot + blr) are invisible
here and need kz_slotscan.py.  Uses skipdata so embedded literal pools do not
desynchronise the sweep.

Usage:
    python kz_blscan.py 24A446 0xfffffe000b348450
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "opencode-temp"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "pylibs"))
import capstone  # noqa: E402
from kc_fstarts import load_build, func_of  # noqa: E402

u = lambda x: x & ((1 << 64) - 1)  # noqa: E731


def main(argv):
    if len(argv) < 3:
        raise SystemExit(__doc__)
    bld = argv[1]
    tgt = int(argv[2], 16)
    kinds = set(argv[3].split(",")) if len(argv) > 3 else {"bl", "b"}
    b = load_build(bld)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True

    segs = []
    for nm, (vm, vsz, fo, fsz) in b["segs"].items():
        if fsz > 0x1000 and ("EXEC" in nm or "__TEXT" in nm) and "LINKEDIT" not in nm:
            segs.append((nm, vm, vsz, fo, fsz))

    hits = []
    for nm, vm, vsz, fo, fsz in segs:
        code = b["data"][fo:fo + fsz]
        for ins in md.disasm(code, vm):
            if ins.mnemonic not in kinds:
                continue
            if not ins.operands or ins.operands[0].type != capstone.arm64.ARM64_OP_IMM:
                continue
            if u(ins.operands[0].imm) == tgt:
                r = func_of(b, ins.address)
                hits.append((nm, ins.address, ins.mnemonic, r))
    print(f"{bld}: {len(hits)} direct {sorted(kinds)} -> {tgt:#x}")
    for nm, va, m, r in hits:
        fs = r[0] if r else 0
        nxt = r[1] if r else 0
        sz = (nxt - fs) if nxt else 0
        print(f"  {nm} {va:#x} ({m})  in func {fs:#x} sz={sz:#x}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

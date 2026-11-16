#!/usr/bin/env python3
"""Find code sites inside a member that build a given VA with ADRP+ADD / ADRP+LDR.

Usage:
    python kz_ref_sites.py <build> <member> <va_hex>
"""
import bisect
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))
import capstone  # noqa: E402
from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM  # noqa: E402
from kc_member import load_member  # noqa: E402

u = lambda x: x & ((1 << 64) - 1)  # noqa: E731
MD = capstone.Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True
MD.skipdata = True


def main(argv):
    if len(argv) < 4:
        raise SystemExit(__doc__)
    bld, member = argv[1], argv[2]
    tgt = int(argv[3], 16)
    b = load_member(bld, member)
    starts = b["starts"]

    def fn(va):
        i = bisect.bisect_right(starts, va) - 1
        return "%#x" % starts[i] if i >= 0 else "-"

    for nm, (vm, vsz, fo, fsz) in sorted(b["segs"].items(), key=lambda x: x[1][0]):
        if "TEXT" not in nm or nm.startswith("__DATA"):
            continue
        blob = b["data"][fo:fo + fsz]
        adrp = {}
        for ins in MD.disasm(blob, vm):
            m = ins.mnemonic
            try:
                ops = ins.operands
            except capstone.CsError:
                continue
            if m == "adrp" and ops:
                adrp[ins.reg_name(ops[0].reg)] = u(ops[1].imm)
            elif m == "add" and len(ops) >= 3 and ops[2].type == ARM64_OP_IMM:
                src = ins.reg_name(ops[1].reg)
                if src in adrp and u(adrp[src] + ops[2].imm) == tgt:
                    print("adrp+add %#x [%s] fn %s" %
                          (ins.address, nm, fn(ins.address)))
            elif m.startswith("ldr") and ops and ops[-1].type == ARM64_OP_MEM \
                    and ops[-1].mem.base == 0:
                if u(ins.address + ops[-1].mem.disp) == tgt:
                    print("literal %#x [%s] fn %s" %
                          (ins.address, nm, fn(ins.address)))


if __name__ == "__main__":
    main(sys.argv)

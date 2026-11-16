#!/usr/bin/env python3
"""Find every site in a fileset member that sets or tests one bit of a qword.

The 27.2 kernel-cache diff added hundreds of `and xD,xN,#~0x100` sites that clear
bit 8 of an object field before dispatch. Whether that idiom is an app-triggerable
defect depends on who SETS bit 8 and what reads it. This enumerates the other half
of the construct - the `orr`/`tst`/`and` sites on the same bit - per member, with
the containing LC_FUNCTION_STARTS function, so the setter can be attributed instead
of guessed at.

Usage:
    python kz_flag_bits.py <build> <member> [bit]     # bit default 8
"""
import bisect
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))
import capstone  # noqa: E402
from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG  # noqa: E402
from kc_member import load_member  # noqa: E402

MD = capstone.Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
MD.detail = True
MD.skipdata = True


def regname(ins, i):
    try:
        return ins.reg_name(ins.operands[i].reg)
    except Exception:
        return None


def main(argv):
    if len(argv) < 3:
        raise SystemExit(__doc__)
    bld, member = argv[1], argv[2]
    bit = int(argv[3]) if len(argv) > 3 else 8
    m = 1 << bit
    b = load_member(bld, member)
    d = b["data"]
    starts = b["starts"]

    def func_of(va):
        i = bisect.bisect_right(starts, va) - 1
        if i < 0:
            return None
        st = starts[i]
        nx = starts[i + 1] if i + 1 < len(starts) else 0
        return st, (nx - st) if nx else 0

    def o2o(va):
        for nm, (vm, vsz, fo, fsz) in b["segs"].items():
            if vm <= va < vm + vsz:
                return fo + (va - vm), nm
        return None, None

    rows = []
    for st in starts:
        end = (starts[bisect.bisect_right(starts, st)]
               if bisect.bisect_right(starts, st) < len(starts) else st + 0x100000)
        off, _ = o2o(st)
        if off is None:
            continue
        blob = d[off:off + min(end - st, 0x20000)]
        for ins in MD.disasm(blob, st):
            try:
                ops = ins.operands
            except capstone.CsError:  # skipdata pseudo-instruction
                continue
            hit = None
            if ins.mnemonic in ("orr", "ands", "tst", "and") and ops:
                last = ops[-1]
                if last.type == ARM64_OP_IMM and (last.imm & ((1 << 64) - 1)) == m:
                    hit = ins.mnemonic
            if ins.mnemonic.startswith("tb") and ops and ops[-1].type == ARM64_OP_IMM:
                if ops[-1].imm == bit:
                    hit = ins.mnemonic
            if not hit:
                continue
            dst = regname(ins, 0)
            srcs = [regname(ins, i) for i in range(len(ops)) if ops[i].type == ARM64_OP_REG]
            # the immediate operand can be the register form too; record raw text
            txt = f"{ins.mnemonic} {ins.op_str}"
            rows.append((func_of(ins.address), hit, ins.address, txt))

    print(f"{bld} {member}: bit {bit} -> {len(rows)} sites")
    byfn = {}
    for fn, kind, va, txt in rows:
        byfn.setdefault(fn, []).append((kind, va, txt))
    for fn in sorted(byfn, key=lambda x: (x[0] or 0)):
        st, sz = fn
        print(f"  fn {st:#x} sz={sz:#x}  ({len(byfn[fn])} sites)")
        for kind, va, txt in byfn[fn][:14]:
            print(f"      {va:#x} {kind:5s} {txt}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

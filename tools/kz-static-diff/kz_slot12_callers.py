#!/usr/bin/env python3
"""Find call sites that dispatch vtable slot 12 (byte offset 0x60) on an object.

Pattern: `ldr xT,[xN,#0x60]` ... within a short window ... `blraa xT(,xM)`.
Arm64e C++ dispatchers reach a virtual method through an authenticated pointer
loaded from the vtable; slot 12 = byte offset 0x60 when slot 0 sits at the vptr.

Usage:
    python kz_slot12_callers.py <build> [member]
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))
import capstone  # noqa: E402
from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402
from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_REG  # noqa: E402


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    bld = argv[1]
    member = argv[2] if len(argv) > 2 else "com.apple.kernel"
    if member == "com.apple.kernel":
        from kc_fstarts import load_build
        b = load_build(bld)
        segs = [(nm, vm, vsz, fo, fsz) for nm, (vm, vsz, fo, fsz) in b["segs"].items() if "__TEXT" in nm]
        data = b["data"]
    else:
        from kc_member import load_member
        b = load_member(bld, member)
        segs = [(nm, vm, vsz, fo, fsz) for nm, (vm, vsz, fo, fsz) in b["segs"].items() if "__TEXT" in nm]
        data = b["data"]
    md = capstone.Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True
    hits = []
    for nm, vm, vsz, fo, fsz in sorted(segs):
        code = data[fo:fo + fsz]
        # collect instructions per segment; keep last 8 for window matching
        pend = []  # list of (addr, regname)
        for ins in md.disasm(code, vm):
            if ins.id == 0:
                pend = []
                continue
            m = ins.mnemonic
            try:
                ops = ins.operands
            except capstone.CsError:
                pend = []
                continue
            if m == "ldr" and len(ops) >= 2 and ops[1].type == ARM64_OP_MEM:
                mem = ops[1].mem
                if mem.base and (mem.disp & 0xffffffff) == 0x60:
                    rt = ins.reg_name(ops[0].reg)
                    rb = ins.reg_name(mem.base)
                    pend.append((ins.address, rt, rb))
                    if len(pend) > 8:
                        pend.pop(0)
                    continue
            if m == "blraa" or m == "braa":
                for addr, rt, rb in pend[-6:]:
                    if ops and ops[0].type == ARM64_OP_REG and ins.reg_name(ops[0].reg) == rt:
                        hits.append((ins.address, addr, rt, rb, m))
                pend = []
                continue
            # mov xT,xS keeps provenance
            if m == "mov" and len(ops) == 2 and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_REG:
                rd = ins.reg_name(ops[0].reg)
                rs = ins.reg_name(ops[1].reg)
                for i, (addr, rt, rb) in enumerate(pend):
                    if rt == rs:
                        pend[i] = (addr, rd, rb)
                continue
            if m.startswith("b") or m == "ret" or m == "retab":
                pend = []
    print(f"{bld} {member}: {len(hits)} slot-0x60 blraa dispatches")
    for h in hits[:80]:
        print(f"  blraa@{h[0]:#x}  ldr@{h[1]:#x}  reg={h[2]} base={h[3]} op={h[4]}")


if __name__ == "__main__":
    main(sys.argv)

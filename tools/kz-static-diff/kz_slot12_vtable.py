#!/usr/bin/env python3
"""Find genuine vtable-slot-12 (byte offset 0x60) dispatches.

Requires the base register of the slot load to have been produced by a plain
`ldr xBase,[xObject]` inside the same small window, so object field loads such as
`ldr x8,[x0,#0x60]` are not mistaken for vtable dispatch.

Usage:
    python kz_slot12_vtable.py <build> [member]
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))
import capstone  # noqa: E402
from capstone import CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402
from capstone.arm64 import ARM64_OP_MEM, ARM64_OP_REG  # noqa: E402


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    bld = argv[1]
    member = argv[2] if len(argv) > 2 else "com.apple.kernel"
    if member == "com.apple.kernel":
        from kc_fstarts import load_build
        b = load_build(bld)
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
        pend = []  # (addr, destreg, kind) kind in {'vptr','slot'}
        for ins in md.disasm(data[fo:fo + fsz], vm):
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
                rt = ins.reg_name(ops[0].reg)
                rb = ins.reg_name(mem.base) if mem.base else None
                if mem.disp == 0 and rb:
                    pend.append((ins.address, rt, "vptr", rb))
                elif mem.disp == 0x60 and rb:
                    pend.append((ins.address, rt, "slot", rb))
                if len(pend) > 12:
                    pend.pop(0)
                continue
            if m in ("blraa", "braa"):
                try:
                    r0 = ins.reg_name(ops[0].reg) if ops and ops[0].type == ARM64_OP_REG else None
                except Exception:
                    r0 = None
                for addr, rt, kind, rb in pend[-8:]:
                    if kind == "slot" and rt == r0:
                        # require the slot base to trace to a vptr load
                        for a2, rt2, k2, rb2 in pend[-8:]:
                            if k2 == "vptr" and rt2 == rb:
                                hits.append((ins.address, addr, rb2, m))
                                break
                pend = []
                continue
            if m == "mov" and len(ops) == 2 and ops[0].type == ARM64_OP_REG and ops[1].type == ARM64_OP_REG:
                rd = ins.reg_name(ops[0].reg)
                rs = ins.reg_name(ops[1].reg)
                for i, p in enumerate(pend):
                    if p[1] == rs:
                        pend[i] = (p[0], rd, p[2], p[3])
                continue
            if m.startswith("b") or m in ("ret", "retab"):
                pend = []
    print(f"{bld} {member}: {len(hits)} vtable slot-0x60 dispatches")
    for h in hits[:120]:
        print(f"  blraa@{h[0]:#x}  slotldr@{h[1]:#x}  obj={h[2]} op={h[3]}")


if __name__ == "__main__":
    main(sys.argv)

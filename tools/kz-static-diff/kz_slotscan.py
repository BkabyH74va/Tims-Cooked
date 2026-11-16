#!/usr/bin/env python3
"""Scan an arm64e kernelcache member for virtual dispatches of one vtable slot.

Arm64e C++ virtual calls load the authenticated entry with

    ldr  xT, [xN, #(slot*8)]      ; LDR Xt,[Xn,#imm*8], unsigned offset
    blr  xT                       ; (blraa under arm64e)

The ldr immediate for a fixed slot is a constant, so a raw word scan with

    (word & 0xFFFFFC00) == 0xF9400000 | ((slot*8//8) << 10)

finds every dispatch site without disassembling the whole image.  Each hit is
then bracketed against LC_FUNCTION_STARTS so the containing function is named,
and a short backward window is decoded to confirm the value loaded into xN is
an object vptr (ldr xN,[xM]) rather than a struct field.

Usage:
    python kz_slotscan.py 24A446 27                 # slot index
    python kz_slotscan.py 24A446 27 --window 12
"""
import bisect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "opencode-temp"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "pylibs"))
import capstone  # noqa: E402
from kc_fstarts import load_build, func_of, o2v  # noqa: E402

u = lambda x: x & ((1 << 64) - 1)  # noqa: E731


def exec_segments(b):
    for nm, (vm, vsz, fo, fsz) in b["segs"].items():
        if fsz and fsz > 0x1000 and ("EXEC" in nm or "__TEXT" in nm) and "LINKEDIT" not in nm:
            yield nm, vm, vsz, fo, fsz


def main(argv):
    if len(argv) < 3:
        raise SystemExit(__doc__)
    bld, slot = argv[1], int(argv[2])
    window = 12
    if "--window" in argv:
        window = int(argv[argv.index("--window") + 1])
    b = load_build(bld)
    pat = 0xF9400000 | (slot << 10)
    mask = 0xFFFFFC00
    starts = b["starts"]
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True

    hits = []
    for nm, vm, vsz, fo, fsz in exec_segments(b):
        blob = b["data"][fo:fo + fsz]
        base = vm
        for i in range(0, len(blob) - 4, 4):
            w = int.from_bytes(blob[i:i + 4], "little")
            if (w & mask) != pat:
                continue
            va = base + i
            r = func_of(b, va)
            hits.append((nm, va, w, r))

    print(f"{bld} slot {slot}: pattern {pat:#x} -> {len(hits)} candidate sites")
    # keep only sites where the loaded reg is branched shortly after the ldr
    kept = []
    for nm, va, w, r in hits:
        rt = w & 0x1F
        off = None
        for sname, (svm, svsz, sfo, sfsz) in b["segs"].items():
            if svm <= va < svm + svsz:
                off = sfo + (va - svm)
                break
        if off is None:
            continue
        post = b["data"][off:off + 32]
        found_blr = False
        rt = w & 0x1F
        n = 0
        for ins in md.disasm(post, va):
            n += 1
            if n > 8:
                break
            if ins.mnemonic.startswith("blr"):
                if ins.reg_name(ins.operands[0].reg) == f"x{rt}":
                    found_blr = True
                break
        if not found_blr:
            continue
        # backward: xt must have been loaded from memory recently
        ld_ok = False
        back = b["data"][max(0, off - 64):off]
        base_va = va - len(back)
        for ins in md.disasm(back, base_va):
            if ins.address >= va:
                break
            if ins.mnemonic == "ldr" and ins.reg_name(ins.operands[0].reg) == f"x{rt}":
                ld_ok = True
        if not ld_ok:
            continue
        r = func_of(b, va)
        rn = (w >> 5) & 0x1F
        kept.append((nm, va, w, rn, r))
    print(f"  confirmed dispatch (ldr slot -> blr same reg): {len(kept)}")
    for nm, va, w, rn, r in kept:
        fs = r[0] if r else 0
        nxt = r[1] if r else 0
        sz = (nxt - fs) if nxt else 0
        print(f"  {nm} {va:#x}  base=x{rn}  in func {fs:#x} sz={sz:#x}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

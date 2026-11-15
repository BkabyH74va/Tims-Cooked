#!/usr/bin/env python3
"""Find ARM64 `cmp wN, #imm` / `cmp xN, #imm` instructions in the IOSurface kext.

Prints each hit with its enclosing function, so selector dispatch tables
(the `switch (selector)` inside an IOExternalMethodDispatch handler) can be
located by their case values.
"""
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
from capstone.arm64 import ARM64_OP_IMM

sys.path.insert(0, str(Path(__file__).parent))
from kc_iosurface import parse_fileset, member_segments, function_starts

KEXT = "com.apple.iokit.IOSurface"


def main():
    kc = Path(sys.argv[1])
    want = {int(x, 0) for x in sys.argv[2:]} or {0x11, 0x12}
    data = kc.read_bytes()
    entries, _ = parse_fileset(data)
    e = [x for x in entries if x["name"] == KEXT][0]
    segs = member_segments(data, e["fileoff"])
    seg = segs.get("__TEXT_EXEC") or segs["__TEXT"]
    base = seg[0]
    text = data[seg[2]:seg[2] + seg[3]]
    fstarts = function_starts(data, e["fileoff"], e["vmaddr"])

    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    def fn_of(addr):
        prev = None
        for f in fstarts:
            if f > addr:
                return prev, f
            prev = f
        return prev, None

    for ins in md.disasm(text, base):
        if ins.mnemonic != "cmp" or not ins.operands:
            continue
        op = ins.operands[1]
        if op.type != ARM64_OP_IMM or op.imm not in want:
            continue
        s, nxt = fn_of(ins.address)
        size = (nxt - s) if nxt else 0
        print(f"0x{ins.address:x}  cmp {ins.op_str}   fn 0x{s:x}..0x{nxt:x} (size {size})")


if __name__ == "__main__":
    main()

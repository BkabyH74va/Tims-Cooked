#!/usr/bin/env python3
"""Context dump around vtable-slot-12 (byte offset 0x60) blraa dispatch sites.

The slot-12 virtual is `IOUserClient::Dispatch(const IORPC rpc)`; its thunk
copies a 0x20-byte `struct IORPC` by value before calling the dispatcher, so
every genuine dispatch site loads `[xV + #0x60]` off an authenticated vptr and
then passes `&stack_copy`. Use this to read how each caller marshals the
`IORPC` -- inline build vs wholesale 32-byte copy.

Usage:
    python kz_slotctx.py <build> <slotldr_va_hex> [slotldr_va_hex ...]
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))
import capstone  # noqa: E402
from kc_fstarts import load_build, v2o, func_of  # noqa: E402

NBACK = 0x90


def main(argv):
    if len(argv) < 3:
        raise SystemExit(__doc__)
    bld = argv[1]
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True
    b = load_build(bld)
    for a in argv[2:]:
        ldr = int(a, 16)
        f = func_of(b, ldr)
        print(f"\n=== slotldr@{ldr:#x} in func {f}")
        if not f:
            continue
        st = f[0]
        lo = max(st, ldr - NBACK)
        off = v2o(b, lo)
        code = b["data"][off:off + (ldr + 8 - lo)]
        for ins in md.disasm(code, lo):
            mark = " <== slot load" if ins.address == ldr else ""
            print(f"  {ins.address:#x}  {ins.mnemonic:<8} {ins.op_str}{mark}")


if __name__ == "__main__":
    main(sys.argv)

#!/usr/bin/env python3
"""Image-wide direct BL/B census to one VA, across every fileset member.

Complements kz_slotscan_all.py (virtual dispatch): catches kext code that links
straight to a kernel symbol instead of going through a vtable.

Usage:
    python kz_blscan_all.py 24A446 0xfffffe000b348450 [bl,b]
"""
import bisect
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "opencode-temp"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "pylibs"))
import capstone  # noqa: E402
from kc_iosurface import parse_fileset, member_load_commands, member_segments  # noqa: E402

BASE = Path("G:/iOS 27.0.1/iOS/firmware")
u = lambda x: x & ((1 << 64) - 1)  # noqa: E731


def load_starts(data, foff, text_vm):
    starts = []
    for cmd, eoff, cmdsize in member_load_commands(data, foff):
        if cmd != 0x26:
            continue
        dataoff = struct.unpack_from("<I", data, eoff + 8)[0]
        size = struct.unpack_from("<I", data, eoff + 12)[0]
        p, end, addr = dataoff, dataoff + size, 0
        while p < end:
            val = shift = 0
            while True:
                b = data[p]
                p += 1
                val |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
            if val == 0:
                break
            addr += val
            starts.append(text_vm + addr)
    return sorted(set(starts))


def main(argv):
    if len(argv) < 3:
        raise SystemExit(__doc__)
    bld = argv[1]
    tgt = int(argv[2], 16)
    kinds = set(argv[3].split(",")) if len(argv) > 3 else {"bl"}
    data = (BASE / bld / "kernelcache.release.macho").read_bytes()
    entries, _ = parse_fileset(data)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True

    total = 0
    hits = []
    for e in entries:
        name, foff = e["name"], e["fileoff"]
        try:
            segs = member_segments(data, foff)
        except Exception:
            continue
        if "__TEXT" not in segs:
            continue
        starts = load_starts(data, foff, segs["__TEXT"][0])

        def func_of(va):
            i = bisect.bisect_right(starts, va) - 1
            if i < 0:
                return None
            st = starts[i]
            nx = starts[i + 1] if i + 1 < len(starts) else 0
            return (st, nx)

        for nm, (vm, vsz, fo, fsz) in segs.items():
            if fsz < 0x100 or ("EXEC" not in nm and "__TEXT" not in nm) or "LINKEDIT" in nm:
                continue
            code = data[fo:fo + fsz]
            for ins in md.disasm(code, vm):
                if ins.mnemonic not in kinds:
                    continue
                if not ins.operands or ins.operands[0].type != capstone.arm64.ARM64_OP_IMM:
                    continue
                if u(ins.operands[0].imm) != tgt:
                    continue
                total += 1
                hits.append((name, ins.address, func_of(ins.address)))
    print(f"{bld}: {total} direct {sorted(kinds)} -> {tgt:#x}")
    for name, va, r in hits[:40]:
        fs = r[0] if r else 0
        nx = r[1] if r else 0
        print(f"  {name} {va:#x} in func {fs:#x} sz={(nx - fs) if nx else 0:#x}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

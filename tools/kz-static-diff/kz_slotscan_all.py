#!/usr/bin/env python3
"""Image-wide census of virtual dispatches of one vtable slot across every
kernelcache fileset member.

Same two-stage method as kz_slotscan.py, but parses the MH_FILESET once instead
of per member.  Only sites that load the slot, branch to it within a few
instructions, and load that register from memory are reported.

Usage:
    python kz_slotscan_all.py 24A446 27
"""
import bisect
import struct
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "opencode-temp"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "pylibs"))
import capstone  # noqa: E402
from kc_iosurface import parse_fileset, member_load_commands, member_segments  # noqa: E402

BASE = Path("G:/iOS 27.0.1/iOS/firmware")


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
    bld, slot = argv[1], int(argv[2])
    pat = 0xF9400000 | (slot << 10)
    mask = 0xFFFFFC00
    data = (BASE / bld / "kernelcache.release.macho").read_bytes()
    entries, _ = parse_fileset(data)
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True

    per_member = defaultdict(list)
    raw_total = 0
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

        def seg_of(va):
            for nm, (vm, vsz, fo, fsz) in segs.items():
                if vm <= va < vm + vsz:
                    return fo + (va - vm)
            return None

        for nm, (vm, vsz, fo, fsz) in segs.items():
            if fsz < 0x100 or ("EXEC" not in nm and "__TEXT" not in nm) or "LINKEDIT" in nm:
                continue
            blob = data[fo:fo + fsz]
            for i in range(0, len(blob) - 4, 4):
                w = int.from_bytes(blob[i:i + 4], "little")
                if (w & mask) != pat:
                    continue
                raw_total += 1
                va = vm + i
                off = seg_of(va)
                if off is None:
                    continue
                rt = w & 0x1F
                br_ok = False
                n = 0
                for ins in md.disasm(data[off:off + 32], va):
                    n += 1
                    if n > 8:
                        break
                    if ins.mnemonic.startswith("blr"):
                        if ins.reg_name(ins.operands[0].reg) == f"x{rt}":
                            br_ok = True
                        break
                if not br_ok:
                    continue
                ld_ok = False
                back = data[max(0, off - 64):off]
                bva = va - len(back)
                for ins in md.disasm(back, bva):
                    if ins.address >= va:
                        break
                    if ins.mnemonic == "ldr" and ins.reg_name(ins.operands[0].reg) == f"x{rt}":
                        ld_ok = True
                if not ld_ok:
                    continue
                per_member[name].append((va, w, func_of(va)))

    print(f"{bld} slot {slot}: raw={raw_total} confirmed={sum(len(v) for v in per_member.values())}")
    for name in sorted(per_member):
        print(f"  {name}: {len(per_member[name])}")
        for va, w, r in per_member[name][:8]:
            fs = r[0] if r else 0
            nx = r[1] if r else 0
            print(f"      {va:#x} base=x{(w >> 5) & 0x1f} in {fs:#x} sz={(nx - fs) if nx else 0:#x}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

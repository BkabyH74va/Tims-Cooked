#!/usr/bin/env python3
"""Word-level BL/B site census to a VA, across every fileset member.

`kz_blscan_all.py` disassembles each executable segment linearly from its base;
capstone's linear sweep can desynchronise on literal pools and silently miss
real sites. This tool instead scans the raw 4-byte words and decodes the BL/B
encoding directly (opcode 0x94000000/0x14000000, imm26 signed, scaled by 4),
so it cannot desynchronise. Reports the containing LC_FUNCTION_STARTS function.

Usage:
    python kz_blw_scan.py <build> <hex-target> [bl,b,blraa]
"""
import bisect
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "opencode-temp"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "pylibs"))
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
    bld, tgt = argv[1], int(argv[2], 16)
    kinds = set(argv[3].split(",")) if len(argv) > 3 else {"bl"}
    data = (BASE / bld / "kernelcache.release.macho").read_bytes()
    entries, _ = parse_fileset(data)

    per_member = {}
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
            return (st, nx - st if nx else 0)

        for nm, (vm, vsz, fo, fsz) in segs.items():
            if fsz < 0x100 or ("EXEC" not in nm and "__TEXT" not in nm) or "LINKEDIT" in nm:
                continue
            blob = data[fo:fo + fsz]
            for i in range(0, len(blob) - 4, 4):
                w = int.from_bytes(blob[i:i + 4], "little")
                op = w & 0xFC000000
                if op not in (0x94000000, 0x14000000):
                    continue
                kind = "bl" if op == 0x94000000 else "b"
                if kind not in kinds:
                    continue
                imm = w & 0x03FFFFFF
                if imm & 0x02000000:
                    imm -= 0x04000000
                site = vm + i
                if site + (imm << 2) != tgt:
                    continue
                r = func_of(site)
                per_member.setdefault(name, []).append(
                    (site, r[0] if r else 0, r[1] if r else 0))

    total = sum(len(v) for v in per_member.values())
    print(f"{bld}: {total} direct ['{','.join(sorted(kinds))}'] -> {tgt:#x}")
    for name in sorted(per_member):
        print(f"  {name}: {len(per_member[name])}")
        for site, fs, sz in per_member[name][:12]:
            print(f"      {site:#x} in {fs:#x} sz={sz:#x}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

#!/usr/bin/env python3
"""Recover function-pointer tables in a kernelcache fileset member.

In Apple kernelcaches, pointers stored in __DATA_CONST / __DATA are either
plain vm addresses or "auth jump" style entries where the low 32 bits hold the
**file offset** of the target inside the kernelcache file.  This script maps
every 8-byte slot of the member's data segments back to a vm address (using
the member's own segment mapping) and prints the slots that land inside the
member's executable text, together with their neighbours.

Usage:
    python kc_meth.py <kernelcache> [kextname] [target_vm]
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from kc_iosurface import parse_fileset, member_segments, LC_SEGMENT_64

KEXT = "com.apple.iokit.IOSurface"


def main():
    kc = Path(sys.argv[1])
    name = sys.argv[2] if len(sys.argv) > 2 else KEXT
    data = kc.read_bytes()
    entries, _ = parse_fileset(data)
    hit = [e for e in entries if e["name"] == name]
    if not hit:
        raise SystemExit(f"{name} not found")
    e = hit[0]
    segs = member_segments(data, e["fileoff"])

    # executable text range + its file-offset mapping
    tex = segs.get("__TEXT_EXEC") or segs["__TEXT"]
    tvm, tvms, tfo, tfs = tex
    # all segments of this member, for fileoff -> vm
    memb = []
    for sname, (vm, vms, fo, fs) in segs.items():
        if fs:
            memb.append((sname, vm, fo, fs))

    def fileoff_to_vm(foff):
        for sname, vm, fo, fs in memb:
            if fo <= foff < fo + fs:
                return vm + (foff - fo)
        return None

    print(f"member {name}: __TEXT_EXEC vm=0x{tvm:x}..0x{tvm+tvms:x} fileoff=0x{tfo:x}")

    targets = set()
    if len(sys.argv) > 3:
        for t in sys.argv[3:]:
            targets.add(int(t, 0))

    for sname in ("__DATA_CONST", "__DATA", "__DATA_DIRTY"):
        if sname not in segs:
            continue
        vm, vms, fo, fs = segs[sname]
        if not fs:
            continue
        print(f"\n== {sname} vm=0x{vm:x} size=0x{fs:x}")
        slots = []
        for off in range(0, fs - 7, 8):
            q = struct.unpack_from("<Q", data, fo + off)[0]
            plain = q & 0x0000FFFFFFFFFFFF
            resolved = None
            if tvm <= plain < tvm + tvms:
                resolved = plain
            else:
                low32 = q & 0xFFFFFFFF
                if low32:
                    r = fileoff_to_vm(low32)
                    if r is not None and tvm <= r < tvm + tvms:
                        resolved = r
            if resolved is not None:
                slots.append((off, vm + off, q, resolved))
        for (off, addr, q, resolved) in slots:
            mark = "  <<<" if resolved in targets else ""
            print(f"  +0x{off:04x} 0x{addr:x}: raw=0x{q:016x} -> 0x{resolved:x}{mark}")
        # print clusters with neighbours
        if slots:
            print("  --- clusters (with context) ---")
            shown = set()
            for (off, addr, q, resolved) in slots:
                if off in shown:
                    continue
                lo = max(0, off - 16)
                hi = min(fs, off + 40)
                for o2 in range(lo, hi, 8):
                    if o2 in shown:
                        continue
                    q2 = struct.unpack_from("<Q", data, fo + o2)[0]
                    plain2 = q2 & 0x0000FFFFFFFFFFFF
                    r2 = None
                    if tvm <= plain2 < tvm + tvms:
                        r2 = plain2
                    else:
                        low32 = q2 & 0xFFFFFFFF
                        if low32:
                            rr = fileoff_to_vm(low32)
                            if rr is not None and tvm <= rr < tvm + tvms:
                                r2 = rr
                    tag = ""
                    if r2 is not None:
                        tag = f" -> fn 0x{r2:x}"
                    elif plain2:
                        tag = f"   raw48=0x{plain2:x}"
                    print(f"    +0x{o2:04x}: 0x{q2:016x}{tag}")
                    shown.add(o2)


if __name__ == "__main__":
    main()

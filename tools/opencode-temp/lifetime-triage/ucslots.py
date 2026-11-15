#!/usr/bin/env python3
"""List the user-client classes owned by one kext (vtables inside the kext's own
__DATA_CONST / __DATA) and show which IOUserClient vtable slots they override."""
import struct
import sys
import resolve as R
import kcq
import kx

BASE_VT = "vtable for IOUserClient"


def vt_addr(syms, name):
    for a, n in syms.items():
        if n == name:
            return a
    return None


def slots(vt_va, n):
    data = R.KC.read_bytes()
    off, nm, sg = kcq.va_to_kc_off(vt_va)
    out = []
    for i in range(n):
        raw = struct.unpack_from("<Q", data, off + i * 8)[0]
        c = R.resolve(raw & 0xFFFFFFFF)
        out.append(c[0][0] if c else None)
    return out


def main():
    member = sys.argv[1]
    base_name = sys.argv[2] if len(sys.argv) > 2 else BASE_VT
    syms = kx.load_symjson()
    m = kx.MachO(kx.EXTRACT / member)
    own = [(s["vmaddr"], s["vmaddr"] + s["vmsize"]) for s in m.segments
           if s["name"] in ("__DATA", "__DATA_CONST")]
    classes = []
    for a, n in sorted(syms.items()):
        if not any(lo <= a < hi for lo, hi in own):
            continue
        if n.startswith("vtable for ") and n.endswith("::MetaClass"):
            continue
        if n.startswith("vtable for ") and "UserClient" in n:
            classes.append((n[len("vtable for "):], a))
    base = vt_addr(syms, base_name)
    print(f"member {member}: base {base_name} @ {base:#018x}")
    bs = slots(base, 0x120)
    for cname, cvt in classes:
        print(f"\n== {cname}  vtable @ {cvt:#018x}")
        cs = slots(cvt, 0x120)
        for i in range(len(cs)):
            if cs[i] != bs[i]:
                b = f"{bs[i]:#018x}" if bs[i] else "None"
                c = f"{cs[i]:#018x}" if cs[i] else "None"
                print(f"   slot {i:3d} (vtable+{i*8:#05x}): base={b} -> {c}")


if __name__ == "__main__":
    main()

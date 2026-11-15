#!/usr/bin/env python3
"""Per-fileset-member kernelcache loader (segments + LC_FUNCTION_STARTS).

`kc_fstarts.load_build()` only covers the `com.apple.kernel` entry. Kext fix sites
(e.g. AppleAVE2) live in their own fileset member with their own segment table and
function starts; this loads one member on the same interface so `func_of`, `v2o`,
`func_refs` and `kc_norm_diff.norm_func` work unchanged.

Usage:
    python kc_member.py 24B119 com.apple.driver.AppleAVE2
"""
import struct, bisect, sys
from pathlib import Path

sys.path.insert(0, "G:/iOS 27.0.1/iOS/tools/opencode-temp")
sys.path.insert(0, "G:/iOS 27.0.1/iOS/tools/pylibs")
from kc_iosurface import parse_fileset, member_load_commands, member_segments

BASE = Path("G:/iOS 27.0.1/iOS/firmware")


def load_member(build, member):
    data = (BASE / build / "kernelcache.release.macho").read_bytes()
    entries, _ = parse_fileset(data)
    e = [x for x in entries if x["name"] == member]
    if not e:
        e = [x for x in entries if member in x["name"]]
    if not e:
        raise SystemExit("member %r not found" % member)
    foff = e[0]["fileoff"]
    segs = member_segments(data, foff)
    starts = []
    for cmd, eoff, cmdsize in member_load_commands(data, foff):
        if cmd != 0x26:
            continue
        dataoff = struct.unpack_from("<I", data, eoff + 8)[0]
        size = struct.unpack_from("<I", data, eoff + 12)[0]
        p = dataoff
        end = dataoff + size
        addr = 0
        while p < end:
            val = 0
            shift = 0
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
            starts.append(segs["__TEXT"][0] + addr)
    starts = sorted(set(starts))
    return {"data": data, "segs": segs, "starts": starts}


def v2o(b, va):
    for nm, (vm, vsz, fo, fsz) in b["segs"].items():
        if vm <= va < vm + vsz:
            return fo + (va - vm)
    raise KeyError(hex(va))


def o2v(b, off):
    for nm, (vm, vsz, fo, fsz) in b["segs"].items():
        if fo <= off < fo + fsz:
            return vm + (off - fo)
    raise KeyError(hex(off))


def func_of(b, va):
    s = b["starts"]
    i = bisect.bisect_right(s, va) - 1
    if i < 0:
        return None
    return s[i], (s[i + 1] if i + 1 < len(s) else None)


if __name__ == "__main__":
    build, member = sys.argv[1], sys.argv[2]
    b = load_member(build, member)
    print("%s %s: %d segments, %d function starts" % (
        build, member, len(b["segs"]), len(b["starts"])))
    for nm, (vm, vsz, fo, fsz) in sorted(b["segs"].items(), key=lambda x: x[1][0]):
        print("   %-20s vm %#x..%#x sz %#x file %#x..%#x" % (
            nm, vm, vm + vsz, vsz, fo, fo + fsz))

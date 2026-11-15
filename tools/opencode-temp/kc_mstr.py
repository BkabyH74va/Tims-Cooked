#!/usr/bin/env python3
"""Print C strings at given VAs inside a named kernelcache fileset member.

Usage: python kc_mstr.py <build> <member> <va_hex> [va_hex ...]
"""
import sys
from pathlib import Path

sys.path.insert(0, r"G:/iOS 27.0.1/iOS/tools/opencode-temp")
sys.path.insert(0, r"G:/iOS 27.0.1/iOS/tools/pylibs")
from kc_iosurface import parse_fileset, member_segments  # noqa: E402

BASE = Path(r"G:/iOS 27.0.1/iOS/firmware")


def main(argv):
    build, member = argv[1], argv[2]
    data = (BASE / build / "kernelcache.release.macho").read_bytes()
    entries, _ = parse_fileset(data)
    match = [e for e in entries if e["name"] == member] or \
            [e for e in entries if member in e["name"]]
    if not match:
        raise SystemExit("member %r not found" % member)
    segs = member_segments(data, match[0]["fileoff"])
    for a in argv[3:]:
        va = int(a, 16)
        got = False
        for nm, (vm, vsz, fo, fsz) in sorted(segs.items()):
            if vm <= va < vm + vsz and nm != "__LINKEDIT":
                off = fo + (va - vm)
                end = data.find(b"\0", off, off + 512)
                raw = data[off:end if end > 0 else off + 128]
                print("%-22s %#x  %r" % (nm, va, raw.decode("ascii", "replace")))
                got = True
                break
        if not got:
            print("(no segment holds %#x)" % va)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

#!/usr/bin/env python3
"""List printable C strings in one fileset member (optionally filtered).

Usage:
    python kz_member_strings.py <build> <member> [substring]
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))
from kc_member import load_member  # noqa: E402


def main(argv):
    if len(argv) < 3:
        raise SystemExit(__doc__)
    bld, member = argv[1], argv[2]
    needle = argv[3] if len(argv) > 3 else None
    b = load_member(bld, member)
    pat = re.compile(rb"[ -~]{5,}")
    seen = set()
    for nm, (vm, vsz, fo, fsz) in sorted(b["segs"].items(), key=lambda x: x[1][0]):
        if nm == "__LINKEDIT":
            continue
        blob = b["data"][fo:fo + fsz]
        for m in pat.finditer(blob):
            s = m.group().decode("ascii")
            if needle and needle.lower() not in s.lower():
                continue
            if s in seen:
                continue
            seen.add(s)
            print("%#x [%s] %s" % (vm + m.start(), nm, s))


if __name__ == "__main__":
    main(sys.argv)

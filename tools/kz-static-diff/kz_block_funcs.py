#!/usr/bin/env python3
"""Map `kz_newfunc_align.py` replace blocks onto containing functions.

The align output reports replace *block* coordinates, which usually sit inside
a larger function. This prints, for every REAL block, the enclosing
LC_FUNCTION_STARTS function on both sides (start, size), so the block can be
attributed and the whole function diffed instead of a fragment.

Usage:
    python kz_block_funcs.py <member> <kz_newfunc_align-output.txt>
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / "tools" / "opencode-temp"))
from kc_member import load_member, func_of  # noqa: E402

PAT = re.compile(
    r"(?:REAL|COUNT-MISMATCH) A@\s*0x([0-9a-f]+)\s+sz\s+(0x[0-9a-f]+)\s*->\s*"
    r"B@\s*0x([0-9a-f]+)\s+sz\s+(0x[0-9a-f]+)"
)


def main(argv):
    if len(argv) < 3:
        raise SystemExit(__doc__)
    member, path = argv[1], argv[2]
    A = load_member("24A446", member)
    B = load_member("24B119", member)
    for ln in Path(path).read_text(errors="replace").splitlines():
        m = PAT.search(ln)
        if not m:
            continue
        a, b = int(m.group(1), 16), int(m.group(3), 16)
        sa, sb = int(m.group(2), 16), int(m.group(4), 16)
        fa, fb = func_of(A, a), func_of(B, b)

        def fmt(f):
            if not f:
                return "no-start"
            return "%#x sz %#x" % (f[0], (f[1] - f[0]) if f[1] else 0)

        print("%s  blkA %#x sz %#x -> fnA %s   |   blkB %#x sz %#x -> fnB %s" %
              (ln.split()[0], a, sa, fmt(fa), b, sb, fmt(fb)))


if __name__ == "__main__":
    main(sys.argv)

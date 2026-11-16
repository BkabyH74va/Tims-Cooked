#!/usr/bin/env python3
"""Summarise the 16 IOSkywalkFamily real edits: identity via string anchors.

Reads an address list (one hex VA per line) and prints, per function, its
LC_FUNCTION_STARTS size, every printable string literal referenced from inside,
and the number of direct BL/B sites plus their targets. Identity comes from
the strings; the call targets are the next analysis step.

Usage:
    python kz_skywalk_id.py 24A446 <addrlist.txt>
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from kz_member_dump import annotate, cstr, seg_of, func_of  # noqa: E402
from kc_member import load_member  # noqa: E402
import io  # noqa: E402

MEMBER = "com.apple.iokit.IOSkywalkFamily"


class Sink:
    def __init__(self):
        self.lines = []

    def write(self, s):
        self.lines.append(s)

    def close(self):
        pass


def main(argv):
    bld = argv[1]
    addrs = [int(x, 16) for x in Path(argv[2]).read_text().split()]
    b = load_member(bld, MEMBER)
    for va in addrs:
        st = func_of(b, va)
        sz = (st[1] - st[0]) if (st and st[1]) else None
        sink = Sink()
        annotate(bld, MEMBER, va, sz or 0x1000, sink)
        strs, calls = [], []
        for ln in sink.lines:
            if "[STRING]" in ln:
                strs.append(ln.split('"')[1] if '"' in ln else ln)
            elif " bl " in ln or " b " in ln:
                parts = ln.split("->")
                if len(parts) == 2:
                    calls.append(parts[1].strip())
        print("FN %#x sz %#x" % (va, sz or 0))
        for s in dict.fromkeys(strs):
            print("    STR %s" % s)
        print("    calls=%d" % len(calls))
        for c in calls[:8]:
            print("      ->%s" % c)


if __name__ == "__main__":
    main(sys.argv)

#!/usr/bin/env python3
"""numpy-free call-graph fingerprint of one function in an annotated dump.

`annot.py` writes addresses with an explicit `0x` prefix, so a BL scanner must
consume that prefix. A pattern starting `^([0-9a-f]+)` cannot match
`0xfffffe...` (the leading `0` satisfies `[0-9a-f]` but then requires whitespace
where `x` sits) and silently reports **zero** calls — read as "no caller".

Usage:
    python annot.py 24A446 0xfffffe000acd1e18 0x20f0 out.s
    python kz_calls.py out.s 0xfffffe000acd1e18 0x20f0 [--targets]
"""
import bisect
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "opencode-temp"))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pylibs"))

BL = re.compile(r'^0x([0-9a-f]+)\s+([0-9a-f]+)\s+bl\s+#0x([0-9a-f]+)')
XOFF = re.compile(r'\[x19, #?(0x[0-9a-f]+)\]')


def load_starts(build=None):
    if not build:
        return None
    from kc_fstarts import load_build
    return load_build(build)["starts"]


def scan(path, va, size, starts=None):
    calls, offs = [], Counter()
    end = va + size
    with open(path, errors="replace") as fh:
        for line in fh:
            m = BL.match(line)
            if m:
                site, tgt = int(m.group(1), 16), int(m.group(3), 16)
                if va <= site < end:
                    calls.append((site, tgt))
            for o in XOFF.findall(line):
                offs[o] += 1
    return calls, offs


def main(argv):
    path = argv[1]
    va, size = int(argv[2], 16), int(argv[3], 16)
    starts = load_starts(argv[4]) if len(argv) > 4 else None
    calls, offs = scan(path, va, size, starts)
    print(f"{os.path.basename(path)} {va:#x}+{size:#x}: {len(calls)} direct BL")
    seen = {}
    for site, tgt in calls:
        key = tgt
        if starts:
            i = bisect.bisect_right(starts, tgt) - 1
            key = starts[i]
        seen.setdefault(key, []).append(site)
    for callee, sites in sorted(seen.items()):
        extra = ""
        if starts:
            i = bisect.bisect_right(starts, callee)
            nxt = starts[i] if i < len(starts) else None
            if nxt:
                extra = f" size={nxt - callee:#x}"
        print(f"  func {callee:#x}{extra} ncalls={len(sites)} sites={[hex(x) for x in sites]}")
    if "--offsets" in argv:
        print("vm_object offsets on x19:")
        for o, n in sorted(offs.items(), key=lambda kv: int(kv[0], 16)):
            print(f"   +{o:<8} {n}")


if __name__ == "__main__":
    main(sys.argv)

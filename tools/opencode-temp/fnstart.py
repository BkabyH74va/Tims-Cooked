#!/usr/bin/env python3
"""For each address argument, print the nearest preceding function prologue
(`bti c` followed by `pacibsp` or `sub sp`) and the function's first insns."""
import sys

PATH = r"G:/REPO\tools\opencode-temp\iosurface_27_0_1.disasm.txt"
lines = open(PATH, "r", encoding="utf-8", errors="replace").read().splitlines()


def addr(line):
    p = line.split(None, 1)
    return p[0].lower() if p else ""


starts = []
for i, line in enumerate(lines):
    if "bti        c" in line:
        # next non-blank line should be pacibsp
        for j in range(i + 1, min(i + 3, len(lines))):
            if "pacibsp" in lines[j] or "sub        sp" in lines[j]:
                starts.append(i)
                break

for target in sys.argv[1:]:
    t = target.lower().lstrip("0x")
    idx = None
    for i, line in enumerate(lines):
        if addr(line) == t:
            idx = i
            break
    if idx is None:
        print("%s: not found" % target)
        continue
    best = None
    for s in starts:
        if s <= idx:
            best = s
        else:
            break
    if best is None:
        print("%s: no prologue" % target)
        continue
    print("%s -> fn start %s" % (target, addr(lines[best])))

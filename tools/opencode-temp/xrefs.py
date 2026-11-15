#!/usr/bin/env python3
"""Find all `bl`/`b` call sites targeting any of the given addresses."""
import sys

PATH = r"G:/REPO\tools\opencode-temp\iosurface_27_0_1.disasm.txt"
lines = open(PATH, "r", encoding="utf-8", errors="replace").read().splitlines()

targets = set()
for t in sys.argv[1:]:
    targets.add("0x" + t.lower().lstrip("0x"))

for line in lines:
    if "bl         #" not in line and "b          #" not in line:
        continue
    p = line.split("#")
    if len(p) < 2:
        continue
    tgt = p[1].strip().split()[0].lower()
    if tgt in targets:
        print(line)

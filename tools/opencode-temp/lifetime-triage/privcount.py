#!/usr/bin/env python3
"""Verify: count of com.apple.private.* strings per extracted kext member.

Usage: privcount.py <kext> [<kext> ...]
"""
import re
import sys
from pathlib import Path

import kx

pat = re.compile(rb"com\.apple\.private\.[A-Za-z0-9_.\-]*")

for name in sys.argv[1:]:
    m = kx.MachO(kx.EXTRACT / name)
    hits = []
    for seg in m.segments:
        if seg["name"] not in ("__TEXT", "__DATA", "__DATA_CONST"):
            continue
        if seg["filesize"] == 0:
            continue
        blob = m.data[seg["fileoff"]:seg["fileoff"] + seg["filesize"]]
        for mo in pat.finditer(blob):
            va = seg["vmaddr"] + mo.start()
            hits.append((va, mo.group().decode("ascii", "replace")))
    uniq = sorted(set(h[1] for h in hits))
    print(f"{name}: {len(uniq)} distinct com.apple.private.* strings")
    for s in uniq:
        print(f"    {s}")

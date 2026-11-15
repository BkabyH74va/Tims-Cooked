#!/usr/bin/env python3
"""Sweep every kernelcache fileset member for carveout / memory-region keywords.

Numpy-free. For each MH_FILESET member, scans its own segments (excluding the
shared __LINKEDIT) for literal byte patterns and reports member, segment,
file offset and VM address of every hit.

Usage:
    python kc_carveout_sweep.py [build] [pattern ...]
"""
import sys
from pathlib import Path

sys.path.insert(0, r"G:/iOS 27.0.1/iOS/tools/opencode-temp")
sys.path.insert(0, r"G:/iOS 27.0.1/iOS/tools/pylibs")
from kc_iosurface import parse_fileset, member_segments  # noqa: E402

BASE = Path(r"G:/iOS 27.0.1/iOS/firmware")

DEFAULT_PATTERNS = [
    b"carveout", b"Carveout", b"CARVEOUT",
    b"PurpleGfxMem", b"ScalableMemory",
    b"getMemoryRegion", b"MemoryRegion", b"memoryRegion",
]


def main(argv):
    build = argv[1] if len(argv) > 1 else "24A446"
    pats = [p.encode() if isinstance(p, str) else p for p in argv[2:]] or DEFAULT_PATTERNS
    data = (BASE / build / "kernelcache.release.macho").read_bytes()
    entries, _ = parse_fileset(data)
    print("build %s: %d members, %d patterns" % (build, len(entries), len(pats)))
    hits = {p: [] for p in pats}
    for e in entries:
        try:
            segs = member_segments(data, e["fileoff"])
        except Exception as exc:                                   # noqa: BLE001
            print("  ! member %s segment parse failed: %s" % (e["name"], exc))
            continue
        for nm, (vm, vsz, fo, fsz) in sorted(segs.items()):
            if nm == "__LINKEDIT":
                continue
            blob = data[fo:fo + fsz]
            for p in pats:
                start = 0
                while True:
                    i = blob.find(p, start)
                    if i < 0:
                        break
                    hits[p].append((e["name"], nm, vm + i, fo + i))
                    start = i + 1
    for p in pats:
        rows = hits[p]
        print("\n== pattern %r : %d hits" % (p.decode(), len(rows)))
        for name, nm, va, off in rows[:80]:
            print("   %-52s %-14s va %#x file %#x" % (name, nm, va, off))
        if len(rows) > 80:
            print("   ... %d more" % (len(rows) - 80))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

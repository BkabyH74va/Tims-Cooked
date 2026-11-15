#!/usr/bin/env python3
"""Dump the IOSurface kext disassembly for any kernelcache.

Usage: python kc_dump_iosurface.py <kernelcache> <out.txt>
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from kc_iosurface import parse_fileset, member_segments, text_of
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

KEXT = "com.apple.iokit.IOSurface"


def main():
    kc = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    data = kc.read_bytes()
    entries, _ = parse_fileset(data)
    hit = [e for e in entries if e["name"] == KEXT]
    if not hit:
        raise SystemExit("IOSurface kext not found")
    e = hit[0]
    segs = member_segments(data, e["fileoff"])
    base, text = text_of(data, segs)
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = False
    lines = []
    for ins in md.disasm(text, base):
        lines.append("%016x  %-10s %s" % (ins.address, ins.mnemonic, ins.op_str))
    txt = "\n".join(lines) + "\n"
    if out:
        out.write_text(txt, encoding="utf-8", errors="replace")
        print("wrote %s (%d lines, base 0x%x)" % (out, len(lines), base))
    else:
        print(txt)


if __name__ == "__main__":
    main()

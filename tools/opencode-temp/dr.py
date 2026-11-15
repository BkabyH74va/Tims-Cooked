#!/usr/bin/env python3
"""Range / function helper for ipsw disassembly dumps.

  python dr.py <disasm.txt> range <lo> <hi>
  python dr.py <disasm.txt> func <addr>          # print the function containing addr
  python dr.py <disasm.txt> grep <regex>
"""
import re
import sys

ADDR = re.compile(r"^0x([0-9a-f]+):\s")
FUNC_START = re.compile(r"\bbti\s+c|\bpacibsp\b|\bpaciasp\b|\bstp\s+fp, lr")


def load(path):
    raw = open(path, "rb").read()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16")
    else:
        text = raw.decode("utf-8", errors="replace")
    out = []
    for ln in text.splitlines():
        m = ADDR.match(ln)
        if not m:
            continue
        out.append((int(m.group(1), 16), ln))
    return out


def main():
    path = sys.argv[1]
    mode = sys.argv[2]
    lines = load(path)
    if mode == "range":
        lo, hi = int(sys.argv[3], 0), int(sys.argv[4], 0)
        for a, ln in lines:
            if lo <= a < hi:
                print(ln)
    elif mode == "grep":
        rx = re.compile(sys.argv[3])
        for a, ln in lines:
            if rx.search(ln):
                print(ln)
    elif mode == "func":
        addr = int(sys.argv[3], 0)
        start = None
        for a, ln in lines:
            if a > addr:
                break
            if FUNC_START.search(ln) and "bti" in ln:
                start = a
        if start is None:
            # fall back: nearest preceding pacibsp
            for a, ln in lines:
                if a > addr:
                    break
                if "pacibsp" in ln:
                    start = a
        end = start + 0x800
        started = False
        for a, ln in lines:
            if a == start:
                started = True
            if started and a < end:
                # stop at the next function start after 2+ instructions
                print(ln)
            if started and a >= end:
                break
    elif mode == "xref":
        target = int(sys.argv[3], 0)
        rx = re.compile(r"(?:b|bl|blr|blraa|b\.)\s+0x([0-9a-f]+)")
        for a, ln in lines:
            m = rx.search(ln)
            if m and int(m.group(1), 16) == target:
                print(ln)


if __name__ == "__main__":
    main()

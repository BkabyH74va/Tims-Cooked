#!/usr/bin/env python3
"""Find adrp/add (and adrp/ldr) references to a target VA in an ipsw disassembly dump.

Usage:
  python xref.py <disasm.txt> <target_va> [more targets...]
"""
import re
import sys

ADDR = re.compile(r"^0x([0-9a-f]+):\s")
ADRP = re.compile(r"adrp\s+(x\d+|w\d+),\s*0x([0-9a-f]+)")
ADD = re.compile(r"add\s+(x\d+),\s*(x\d+),\s*#(0x[0-9a-f]+|\d+)")
LDR = re.compile(r"ldr\s+(x\d+),\s*\[(x\d+),\s*#(0x[0-9a-f]+|\d+)\]")


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
        body = ln[m.end():]
        out.append((int(m.group(1), 16), body))
    return out


def main():
    path = sys.argv[1]
    targets = {int(t, 0) for t in sys.argv[2:]}
    pages = {t & ~0xFFF for t in targets}
    lines = load(path)
    # reg -> page map, reset per basic-block-ish window (we just track last adrp per reg)
    regpage = {}
    for addr, body in lines:
        m = ADRP.search(body)
        if m:
            reg = m.group(1)
            page = int(m.group(2), 16)
            regpage[reg] = page
        m2 = ADD.search(body)
        if m2:
            dst, src, imm = m2.group(1), m2.group(2), int(m2.group(3), 0)
            if src in regpage:
                val = regpage[src] + imm
                if val in targets:
                    print(f"ADD  {addr:#018x}  {body.strip()}   -> {val:#018x}")
        m3 = LDR.search(body)
        if m3:
            dst, src, imm = m3.group(1), m3.group(2), int(m3.group(3), 0)
            if src in regpage:
                val = regpage[src] + imm
                if val in targets:
                    print(f"LDR  {addr:#018x}  {body.strip()}   -> {val:#018x}")


if __name__ == "__main__":
    main()

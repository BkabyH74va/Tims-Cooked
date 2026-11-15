#!/usr/bin/env python3
"""f1iogpu_oslog.py -- for a kext, find code xrefs to each __TEXT.__os_log string
and print the surrounding function.

usage: f1iogpu_oslog.py <disasm.txt> <strings.txt> [regex]
"""
import re
import sys
from pathlib import Path

ADDR = re.compile(r"^0x([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*(\S.*)?$")
ADRP = re.compile(r"^adrp\s+(x\d+), 0x([0-9a-f]+)$")
ADD = re.compile(r"^add\s+(x\d+), (x\d+), #(0x[0-9a-f]+)$")
LDR = re.compile(r"^ldr\s+[xwq]\d+, (x\d+), #(0x[0-9a-f]+)$")


def load(path):
    raw = Path(path).read_bytes()
    txt = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8", "replace")
    out = []
    for ln in txt.splitlines():
        m = ADDR.match(ln)
        if m:
            out.append((int(m.group(1), 16), ln, (m.group(3) or "").strip()))
    return out


def func_start(ins, addr):
    start = None
    for a, ln, body in ins:
        if a > addr:
            break
        if body.startswith("bti") or "pacibsp" in body or "paciasp" in body or "pacibsp" in body:
            start = a
    return start


def main():
    dis, strs = sys.argv[1], sys.argv[2]
    rx = re.compile(sys.argv[3]) if len(sys.argv) > 3 else None
    ins = load(dis)
    targets = {}
    raw = Path(strs).read_bytes()
    txt = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8", "replace")
    for ln in txt.splitlines():
        parts = ln.split(" ", 2)
        if len(parts) < 3:
            continue
        va = int(parts[0], 16)
        s = parts[2]
        if "__os_log" not in parts[1]:
            continue
        if rx and not rx.search(s):
            continue
        targets[va] = s

    regpage = {}
    refs = {}
    for idx, (a, ln, body) in enumerate(ins):
        m = ADRP.match(body)
        if m:
            regpage[m.group(1)] = (int(m.group(2), 16), idx)
            continue
        for rxx in (ADD, LDR):
            m = rxx.match(body)
            if m:
                if rxx is ADD:
                    dst, src, imm = m.group(1), m.group(2), int(m.group(3), 16)
                else:
                    dst, src, imm = None, m.group(1), int(m.group(2), 16)
                pg = regpage.get(src)
                if pg and idx - pg[1] <= 8:
                    val = (pg[0] + imm) & 0xFFFFFFFFFFFFFFFF
                    if dst:
                        regpage[dst] = (val & ~0xFFF, idx)
                    if val in targets:
                        refs.setdefault(val, []).append(a)
                break

    for va, s in sorted(targets.items()):
        rs = refs.get(va, [])
        print(f"\n######## {va:#018x}  {s}")
        for r in rs:
            fs = func_start(ins, r)
            print(f"   xref at {r:#018x}   func start ~ {fs:#018x}")


if __name__ == "__main__":
    main()

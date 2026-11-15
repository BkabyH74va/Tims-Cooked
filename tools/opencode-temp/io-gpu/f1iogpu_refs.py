#!/usr/bin/env python3
"""f1iogpu_refs.py -- find ADRP+ADD/LDR references to a target VA in a disassembly dump,
and/or search for immediate constants.

usage:
  f1iogpu_refs.py refs <disasm.txt> <target_va_hex>
  f1iogpu_refs.py imm <disasm.txt> <hexvalue>       # find "mov wN, #val" style immediates
  f1iogpu_refs.py fn  <disasm.txt> <addr_hex>       # print the function containing addr
"""
import re
import sys
from pathlib import Path

ADDR = re.compile(r"^0x([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*(\S.*)?$")
ADRP = re.compile(r"^adrp\s+(x\d+), 0x([0-9a-f]+)$")
ADD = re.compile(r"^add\s+(x\d+), (x\d+), #(0x[0-9a-f]+)$")
LDR = re.compile(r"^ldr\s+[xwq]\d+, (x\d+), #(0x[0-9a-f]+)$")
MOVI = re.compile(r"^mov[zk]\s+w\d+, #(0x[0-9a-f]+)$")
MOVK = re.compile(r"^movk\s+w\d+, #(0x[0-9a-f]+), lsl #(\d+)$")
CMP = re.compile(r"^cmp\s+w\d+, #(0x[0-9a-f]+)$")


def load(path):
    raw = Path(path).read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        txt = raw.decode("utf-16")
    else:
        txt = raw.decode("utf-8", errors="replace")
    out = []
    for ln in txt.splitlines():
        m = ADDR.match(ln)
        if m:
            out.append((int(m.group(1), 16), ln, (m.group(3) or "").strip()))
    return out


def refs(ins, target):
    regpage = {}
    recent = {}
    for idx, (a, ln, body) in enumerate(ins):
        m = ADRP.match(body)
        if m:
            regpage[m.group(1)] = (int(m.group(2), 16), idx)
            continue
        for rx in (ADD, LDR):
            m = rx.match(body)
            if m:
                if rx is ADD:
                    dst, src, imm = m.group(1), m.group(2), int(m.group(3), 16)
                else:
                    dst, src, imm = None, m.group(1), int(m.group(2), 16)
                pg = regpage.get(src)
                if pg and idx - pg[1] <= 8:
                    val = (pg[0] + imm) & 0xFFFFFFFFFFFFFFFF
                    if dst:
                        regpage[dst] = (val & ~0xFFF, idx)
                    if val == target:
                        print(f"REF  {ln}")
                break


def imm(ins, val):
    for a, ln, body in ins:
        for rx in (MOVI, CMP):
            m = rx.match(body)
            if m and int(m.group(1), 16) == val:
                print(f"IMM  {ln}")


def func(ins, addr):
    start = None
    for a, ln, body in ins:
        if a <= addr:
            if body.startswith("bti") or "pacibsp" in body or "paciasp" in body:
                start = a
        elif start is not None and a > addr:
            break
    if start is None:
        print("no start found")
        return
    for a, ln, body in ins:
        if a < start:
            continue
        if a > start + 0x2000:
            break
        print(ln)


if __name__ == "__main__":
    mode, path = sys.argv[1], sys.argv[2]
    ins = load(path)
    if mode == "refs":
        refs(ins, int(sys.argv[3], 0))
    elif mode == "imm":
        imm(ins, int(sys.argv[3], 0))
    elif mode == "fn":
        func(ins, int(sys.argv[3], 0))

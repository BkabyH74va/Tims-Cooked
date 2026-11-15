#!/usr/bin/env python3
"""f1iogpu: find code references (adrp+add / ldr of string) in the IOGPUFamily
disassembly to a given target VA, and map VA -> string for the kext's cstring.

usage:
  f1iogpu_xref.py <target_va_hex>       # find refs to VA
  f1iogpu_xref.py --str "some substring"  # list cstring entries matching
"""
import re
import sys
from pathlib import Path

DIS = Path(r"G:/REPO\tools\opencode-temp\io-gpu\iogpu.disasm.txt")
STR = Path(r"G:/REPO\tools\opencode-temp\io-gpu\iogpu.strings.txt")

LINES = DIS.read_bytes().decode("utf-8", errors="replace").splitlines()
ADDR = re.compile(r"^0x([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*(\S.*)?$")


def parse():
    out = []
    for ln in LINES:
        m = ADDR.match(ln)
        if m:
            out.append((int(m.group(1), 16), ln, (m.group(3) or "").strip()))
    return out


def main():
    ins = parse()
    if sys.argv[1] == "--str":
        pat = sys.argv[2]
        raw = STR.read_bytes()
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            txt = raw.decode("utf-16")
        else:
            txt = raw.decode("utf-8", errors="replace")
        for ln in txt.splitlines():
            if pat.lower() in ln.lower():
                print(ln)
        return

    target = int(sys.argv[1], 0)
    # pass 1: find all adrp instructions whose page == target page
    page = target & ~0xFFF
    lo = target & 0xFFF
    # We do the standard adrp+add window analysis:
    # for each adrp at addr A with page P, and add/ldr at A+4..A+16 with imm I,
    # resolved = P + I
    adrp = re.compile(r"^adrp\s+(x\d+|x\d\d), 0x([0-9a-f]+)$")
    addi = re.compile(r"^add\s+(x\d+), (x\d+), #(0x[0-9a-f]+)$")
    ldr = re.compile(r"^ldr\s+(x\d+), (x\d+), #(0x[0-9a-f]+)$")
    ldrw = re.compile(r"^ldr\s+w\d+, (x\d+), #(0x[0-9a-f]+)$")

    regs = {}
    for idx, (a, ln, body) in enumerate(ins):
        m = adrp.match(body)
        if m:
            regs[m.group(1)] = int(m.group(2), 16)
            continue
        for rx in (addi, ldr, ldrw):
            m = rx.match(body)
            if m:
                dst, src, imm = m.group(1), m.group(2), int(m.group(3), 16)
                if src in regs:
                    val = (regs[src] + imm) & 0xFFFFFFFFFFFFFFFF
                    regs[dst] = val
                    if val == target:
                        print(f"REF  {ln}   (resolved {val:#x})")
                break


if __name__ == "__main__":
    main()

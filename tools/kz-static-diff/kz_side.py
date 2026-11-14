#!/usr/bin/env python3
"""Side-by-side semantic diff of two annotated dumps.

Normalises away:
  - absolute VAs and ADRP page values
  - file/line immediates (the 0x2xxx 'assert id' constants)
Keeps: mnemonics, registers, memory offsets, call targets (as function ids),
and resolved string/data annotations.
"""
import difflib
import re
import sys


def norm(line):
    s = line.rstrip()
    # drop VA + bytes columns
    s = re.sub(r'^[0-9a-f]{16}\s+[0-9a-f]{8}\s+', '', s)
    # annotate branch/call targets as F<hex-of-target-lowbits> so equal targets match
    s = re.sub(r'(CALL|FUNC) ([0-9a-f]{16})', lambda m: f"{m.group(1)} {int(m.group(2),16)&0xffffff:x}", s)
    # normalise any remaining absolute hex >= 0xfffffe to a stable id
    s = re.sub(r'0xfffffe0[0-9a-f]{7}', '#VA', s)
    s = re.sub(r'-0x[0-9a-f]+', '#NEG', s)
    # assert-id style immediates 0x2xxx / 0x5xx: keep only small set
    s = re.sub(r'#(0x2[0-9a-f]{3}|0x5[0-9a-f]{2})\b', '#LINEID', s)
    return s


def main():
    A = [norm(x) for x in open(sys.argv[1])]
    B = [norm(x) for x in open(sys.argv[2])]
    sm = difflib.SequenceMatcher(a=A, b=B, autojunk=False)
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        print(f"\n### {tag}  A[{i1}:{i2}] B[{j1}:{j2}]")
        for k in range(max(0, i1 - 3), min(len(A), i2 + 3)):
            mark = "*" if i1 <= k < i2 else " "
            print(f" {mark}A{k:4d} {A[k]}")
        print("   ---")
        for k in range(max(0, j1 - 3), min(len(B), j2 + 3)):
            mark = "*" if j1 <= k < j2 else " "
            print(f" {mark}B{k:4d} {B[k]}")


if __name__ == "__main__":
    main()

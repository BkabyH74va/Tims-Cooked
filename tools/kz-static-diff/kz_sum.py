#!/usr/bin/env python3
"""Compact change-block summary between two annotated dumps."""
import difflib
import re
import sys


def norm(line):
    s = line.rstrip()
    s = re.sub(r'^[0-9a-f]{16}\s+[0-9a-f]{8}\s+', '', s)
    s = re.sub(r'(CALL|FUNC) [0-9a-f]{16}', lambda m: f"{m.group(1)} <id>", s)
    s = re.sub(r'0xfffffe[0-9a-f]+', '#VA', s)
    s = re.sub(r'-0x[0-9a-f]+', '#NEG', s)
    s = re.sub(r'#(?:0x)?2[0-9a-f]{3}\b', '#LINEID', s)
    return s


def main():
    A = [norm(x) for x in open(sys.argv[1])]
    B = [norm(x) for x in open(sys.argv[2])]
    sm = difflib.SequenceMatcher(a=A, b=B, autojunk=False)
    ops = [o for o in sm.get_opcodes() if o[0] != "equal"]
    print(f"# {len(ops)} change blocks")
    for n, (tag, i1, i2, j1, j2) in enumerate(ops[:60]):
        da, db = i2 - i1, j2 - j1
        print(f"\n[{n}] {tag} A[{i1}:{i2}]({da}) B[{j1}:{j2}]({db})")
        for k in range(i1, min(i2, i1 + 3)):
            print(f"    A {A[k]}")
        if da > 3:
            print("    ...")
        for k in range(j1, min(j2, j1 + 3)):
            print(f"    B {B[k]}")
        if db > 3:
            print("    ...")


if __name__ == "__main__":
    main()

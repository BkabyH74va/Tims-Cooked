#!/usr/bin/env python3
"""List change blocks sorted by size, no instruction text."""
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
    rows = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        rows.append((max(i2 - i1, j2 - j1), tag, i1, i2, j1, j2))
    rows.sort(reverse=True)
    for n, (sz, tag, i1, i2, j1, j2) in enumerate(rows[:25]):
        print(f"[{n}] maxlen={sz:5d} {tag:7s} A[{i1}:{i2}]({i2-i1}) B[{j1}:{j2}]({j2-j1})")


if __name__ == "__main__":
    main()

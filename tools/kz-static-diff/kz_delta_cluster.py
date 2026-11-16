#!/usr/bin/env python3
"""Cluster the genuine code deltas inside a member's cross-build replace blocks.

For every non-equal block whose instruction *shape* also differs (i.e. real code,
not struct-layout drift), record the exact A-side and B-side instruction text
with rebase-sensitive operands masked. Blocks with identical text are grouped so
a single systemic change (for example a new flag-clear idiom) is counted once
instead of hundreds of times.

Usage:
    python kz_delta_cluster.py <member> <align-output.txt> [topN]
"""
import difflib
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import kz_fn_classify as fc  # noqa: E402


def text(insns):
    return " | ".join("%s %s" % (i.mnemonic, fc.norm(i.op_str)) for _, i in insns)


def main(argv):
    if len(argv) < 3:
        raise SystemExit(__doc__)
    member, path = argv[1], argv[2]
    topn = int(argv[3]) if len(argv) > 3 else 25
    groups = Counter()
    examples = {}
    for ln in Path(path).read_text(errors="replace").splitlines():
        m = fc.ALIGN_PAT.search(ln)
        if not m:
            continue
        na, nb = int(m.group(1)), int(m.group(2))
        asz = int(m.group(3), 0)
        bsz = int(m.group(4), 0)
        ava, bva = int(m.group(5), 16), int(m.group(7), 16)
        code, _drift = fc.analyse(member, ava, bva, asz, bsz)
        for tag, aa, ba, an, bn in code:
            pass
        # recompute with raw streams so we can capture exact text per opcode
        Ai = fc.ins_list("24A446", member, ava, asz)
        Bi = fc.ins_list("24B119", member, bva, bsz)
        ka = [(i.mnemonic, fc.norm(i.op_str)) for _, i in Ai]
        kb = [(i.mnemonic, fc.norm(i.op_str)) for _, i in Bi]
        sm = difflib.SequenceMatcher(None, ka, kb, autojunk=False)
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == "equal":
                continue
            sa = tuple(fc.shape(i) for _, i in Ai[i1:i2])
            sb = tuple(fc.shape(i) for _, i in Bi[j1:j2])
            if sa == sb:
                continue
            key = (text(Ai[i1:i2]), text(Bi[j1:j2]))
            groups[key] += 1
            if key not in examples:
                examples[key] = (Ai[i1][0] if i1 < i2 else None,
                                 Bi[j1][0] if j1 < j2 else None, i2 - i1, j2 - j1)
    print("distinct code deltas: %d (total instances %d)" %
          (len(groups), sum(groups.values())))
    for n, (key, cnt) in enumerate(groups.most_common(topn), 1):
        atxt, btxt = key
        ex = examples[key]
        print("\n=== #%d x%d   A@%s (%d) -> B@%s (%d)" %
              (n, cnt, hex(ex[0]) if ex[0] else "-", ex[2],
               hex(ex[1]) if ex[1] else "-", ex[3]))
        print("  A: %s" % (atxt[:600] or "(none)"))
        print("  B: %s" % (btxt[:600] or "(none)"))


if __name__ == "__main__":
    main(sys.argv)

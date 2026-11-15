#!/usr/bin/env python3
"""Fingerprint a kernelcache member function and find its counterpart in another build.

Compares relocation/line-normalised instruction streams (kc_norm_diff.norm_func)
so address drift between builds does not matter. Exact hash equality means the
function is unchanged; otherwise the nearest candidates by difflib ratio are shown.

Usage:
    python kc_fnfp_find.py <member> <buildA:va_hex:size_hex> [<buildA:va_hex:size_hex> ...]
Builds are fixed to 24A446 (source) and 24B119 (target).
"""
import difflib
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, r"G:/iOS 27.0.1/iOS/tools/opencode-temp")
sys.path.insert(0, r"G:/iOS 27.0.1/iOS/tools/pylibs")
from kc_member import load_member, v2o              # noqa: E402
from kc_norm_diff import norm_func                  # noqa: E402

BUILDS = ("24A446", "24B119")


def fp(b, va, size):
    return "\n".join(norm_func(b, va, size))


def main(argv):
    if len(argv) < 3:
        raise SystemExit(__doc__)
    member = argv[1]
    targets = []
    for spec in argv[2:]:
        parts = spec.split(":")
        targets.append((parts[0], int(parts[1], 16), int(parts[2], 16)))
    A = load_member(BUILDS[0], member)
    B = load_member(BUILDS[1], member)
    print("%s: A starts=%d B starts=%d" % (member, len(A["starts"]), len(B["starts"])))

    bfuncs = []
    for i, s in enumerate(B["starts"]):
        e = B["starts"][i + 1] if i + 1 < len(B["starts"]) else None
        if e:
            bfuncs.append((s, e - s))

    for build, va, size in targets:
        if build != BUILDS[0]:
            continue
        fa = fp(A, va, size)
        h = hashlib.sha256(fa.encode()).hexdigest()[:16]
        print("\n== A %#x size %#x fp=%s" % (va, size, h))
        exact = [(s, z) for (s, z) in bfuncs
                 if hashlib.sha256(fp(B, s, z).encode()).hexdigest()[:16] == h]
        if exact:
            for s, z in exact:
                print("   EXACT match in B: %#x size %#x" % (s, z))
            continue
        # no exact match: report best few by similarity, only for similar sizes
        cands = []
        for s, z in bfuncs:
            if abs(z - size) > max(size, z) * 0.6:
                continue
            fb = fp(B, s, z)
            r = difflib.SequenceMatcher(None, fa, fb).ratio()
            cands.append((r, s, z))
        cands.sort(reverse=True)
        for r, s, z in cands[:5]:
            print("   close: B %#x size %#x ratio=%.3f (A size %#x)" % (s, z, r, size))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

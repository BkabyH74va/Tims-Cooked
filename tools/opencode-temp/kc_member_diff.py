#!/usr/bin/env python3
"""Pairwise function-level diff of one kernelcache fileset member across builds.

Numpy-free. Uses LC_FUNCTION_STARTS per member (kc_member.load_member) and the
relocation-normalised instruction comparison from kc_norm_diff.norm_func.

Usage:
    python kc_member_diff.py com.apple.iokit.IOSurface
    python kc_member_diff.py com.apple.driver.AppleAVE2 24A446:0xfffffe000878e220
"""
import sys

sys.path.insert(0, "G:/iOS 27.0.1/iOS/tools/opencode-temp")
sys.path.insert(0, "G:/iOS 27.0.1/iOS/tools/pylibs")
from kc_member import load_member, v2o          # noqa: E402
from kc_norm_diff import norm_func              # noqa: E402

BUILDS = ("24A446", "24B119")


def funcs(b):
    s = b["starts"]
    return [(s[i], s[i + 1] if i + 1 < len(s) else None) for i in range(len(s))]


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    member = argv[1]
    A = load_member(BUILDS[0], member)
    B = load_member(BUILDS[1], member)
    print("%s: %d segments / %d starts (A), %d starts (B)" % (
        member, len(A["segs"]), len(A["starts"]), len(B["starts"])))
    for nm, (vm, vsz, fo, fsz) in sorted(A["segs"].items(), key=lambda x: x[1][0]):
        print("   %-16s vm %#x..%#x sz %#x file %#x..%#x" % (
            nm, vm, vm + vsz, vsz, fo, fo + fsz))

    fa, fb = funcs(A), funcs(B)
    n = min(len(fa), len(fb))
    changed = []
    for i in range(n):
        sa, ea = fa[i]
        sb, eb = fb[i]
        if not ea or not eb:
            continue
        za, zb = ea - sa, eb - sb
        if za != zb:
            changed.append((i, sa, sb, za, zb, "SIZE"))
            continue
        if norm_func(A, sa, za) != norm_func(B, sb, zb):
            changed.append((i, sa, sb, za, zb, "CODE"))

    print("pairs=%d changed=%d" % (n, len(changed)))
    for c in changed:
        print("  idx=%d A=%#x sz=%#x B=%#x %s" % (c[0], c[1], c[3], c[2], c[5]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
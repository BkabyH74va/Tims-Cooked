#!/usr/bin/env python3
"""Find data slots (plain or arm64e-auth) inside a member that point at a VA.

Usage:
    python kz_ptr_slots.py <build> <member> <hex-va>
"""
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools" / "opencode-temp"))
sys.path.insert(0, str(ROOT / "tools" / "pylibs"))
from kc_member import load_member  # noqa: E402

MASK32 = 0xFFFFFFFF


def main(argv):
    if len(argv) < 4:
        raise SystemExit(__doc__)
    bld, member = argv[1], argv[2]
    tgt = int(argv[3], 16)
    b = load_member(bld, member)
    text_vm = b["segs"]["__TEXT"][0]
    data = b["data"]
    for nm, (vm, vsz, fo, fsz) in b["segs"].items():
        blob = data[fo:fo + fsz]
        for off in range(0, len(blob) - 8, 8):
            e = struct.unpack_from("<Q", blob, off)[0]
            plain = e == tgt
            auth = (e >> 32) != 0 and text_vm + (e & MASK32) == tgt
            if plain or auth:
                print("%#x [%s] %#018x %s" % (vm + off, nm, e,
                                              "plain" if plain else "auth"))


if __name__ == "__main__":
    main(sys.argv)

#!/usr/bin/env python3
"""Decode the prelinked chained-fixup pointers in a kext's __DATA_CONST.__const
and dump them as an annotated table.

The 27.0.1 kernelcache is prelinked: every kext's data pointers are chained
fixups relative to the *global* kernelcache image base 0xfffffe0007000000
(the vmaddr of the first fileset member `com.apple.kernel` = 0xfffffe000700c000
rounded down to 0x1000000).
"""
import struct
import sys

sys.path.insert(0, r"G:/REPO\tools\opencode-temp")
from kc import IOSURFACE, IOMGF, macho_sections

BASE = 0xFFFFFE0007000000


def decode(word):
    """Return (target_va, kind) for a prelinked chained-fixup word."""
    low = word & 0xFFFFFFFF
    target = BASE + low
    # chained fixup header bits
    next_ = (word >> 33) & 1
    bind = (word >> 34) & 3
    auth = (word >> 36) & 1
    stride = word >> 37
    high8 = (word >> 24) & 0xFF
    kind = f"bind={bind} auth={auth} next={next_} stride={stride} high8={high8:#x}"
    return target, kind


def main():
    path = {"ios": IOSURFACE, "iomgf": IOMGF}[sys.argv[1] if len(sys.argv) > 1 else "ios"]
    want = sys.argv[2] if len(sys.argv) > 2 else None
    data = path.read_bytes()
    secs = macho_sections(data)
    text = None
    for seg, sect, addr, size, off in secs:
        if seg == "__TEXT_EXEC" and sect == "__text":
            text = (addr, addr + size)
    for seg, sect, addr, size, off in secs:
        if want and not (seg == want or sect == want):
            continue
        print(f"=== {seg}.{sect}  va={addr:#018x} size={size:#x} off={off:#x}")
        for i in range(0, size - 7, 8):
            (word,) = struct.unpack_from("<Q", data, off + i)
            target, kind = decode(word)
            mark = ""
            if text and text[0] <= target < text[1]:
                mark = "  <TEXT_EXEC>"
            print(f"{addr+i:#018x}: {word:#018x} -> {target:#018x}{mark}   {kind}")


if __name__ == "__main__":
    main()

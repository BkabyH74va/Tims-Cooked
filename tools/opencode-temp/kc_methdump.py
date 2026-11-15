#!/usr/bin/env python3
"""Dump + decode the IOSurface kext's external-method dispatch table.

The table lives in the kext's __DATA_CONST.  Entries are 40 bytes and look
like an `IOExternalMethodDispatch` variant:

    +0x00 uint64  handler function (kernel vm address, PAC-stripped)
    +0x08 uint32  checkScalarInputCount
    +0x0c uint32  checkStructInputCount
    +0x10 uint32  checkScalarOutputCount
    +0x14 uint32  checkStructOutputCount
    ...

Usage:
    python kc_methdump.py <kernelcache> <first-index> <count>
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from kc_iosurface import parse_fileset, member_segments

KEXT = "com.apple.iokit.IOSurface"
STRIDE = 40


def main():
    kc = Path(sys.argv[1])
    first = int(sys.argv[2], 0)
    count = int(sys.argv[3], 0)
    data = kc.read_bytes()
    entries, _ = parse_fileset(data)
    e = [x for x in entries if x["name"] == KEXT][0]
    segs = member_segments(data, e["fileoff"])
    dc = segs["__DATA_CONST"]
    dcvm, dcvms, dcfo, dcfs = dc

    # the table base discovered earlier
    TABLE_OFF = 0x2638
    base_vm = dcvm + TABLE_OFF
    base_fo = dcfo + TABLE_OFF

    print('__DATA_CONST vm=0x%x size=0x%x' % (dcvm, dcvms))
    print('table base vm=0x%x fileoff=0x%x' % (base_vm, base_fo))

    for i in range(first, first + count):
        off = base_fo + i * STRIDE
        raw = data[off:off + STRIDE]
        vals = struct.unpack_from('<5Q', raw)
        u32 = struct.unpack_from('<10I', raw)
        print('\nentry %d (selector 0x%x) vm=0x%x' % (i, i, base_vm + i * STRIDE))
        print('  raw: %s' % raw.hex(' '))
        print('  u64: %s' % ' '.join('0x%x' % v for v in vals))
        print('  u32: %s' % ' '.join('0x%x' % v for v in u32))


if __name__ == '__main__':
    main()

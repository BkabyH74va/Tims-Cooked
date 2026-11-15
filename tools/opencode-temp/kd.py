#!/usr/bin/env python3
"""Disassemble arbitrary VAs in the extracted IOSurface kext."""
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN

B = open(r'G:/REPO\tools\opencode-temp\iosurface-extract\com.apple.iokit.IOSurface','rb').read()
TEXT_OFF  = 0x8000
TEXT_ADDR = 0xfffffe000a3257c0
TEXT_SIZE = 0x3461c

def va2off(va):
    return TEXT_OFF + (va - TEXT_ADDR)

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)

def dump(va, count=200, label=''):
    off = va2off(va)
    blob = B[off:off+count*4]
    print('='*30, label or hex(va), '='*30)
    n = 0
    for insn in md.disasm(blob, va):
        print('  %018x: %-8s %s' % (insn.address, insn.mnemonic, insn.op_str))
        n += 1
        if n >= count:
            break
    print()

if __name__ == '__main__':
    for a in sys.argv[1:]:
        va = int(a, 16)
        dump(va, 140)

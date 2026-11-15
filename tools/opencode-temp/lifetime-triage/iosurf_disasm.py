from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
import sys
sys.path.insert(0, r'G:/REPO\tools\opencode-temp')
from kc import IOSURFACE, macho_sections

data = IOSURFACE.read_bytes()
secs = macho_sections(data)
text_off = 0x8000
text_addr = 0xfffffe000a3257c0

def va2off(va):
    return text_off + (va - text_addr)

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
md.detail = True

handlers = {
    'sel0':  0xfffffe000a345114,
    'sel9':  0xfffffe000a3453b4,
    'sel10': 0xfffffe000a3454cc,
    'sel11': 0xfffffe000a3456dc,
    'sel19': 0xfffffe000a345934,
    'sel24': 0xfffffe000a345b48,
    'sel26': 0xfffffe000a345cd0,
    'sel46': 0xfffffe000a346300,
    'sel47': 0xfffffe000a346464,
    'sel48': 0xfffffe000a34657c,
    'sel50': 0xfffffe000a346740,
    'sel54': 0xfffffe000a3467e4,
}

for name, va in handlers.items():
    off = va2off(va)
    blob = data[off:off+400]
    print(f'=== {name} @ {va:#018x} ===')
    for insn in md.disasm(blob, va):
        print(f'  {insn.address:#018x}: {insn.mnemonic:8s} {insn.op_str}')
        if insn.address - va > 300:
            break
    print()

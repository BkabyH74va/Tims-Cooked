import re, sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

log = open(r'G:/REPO\tools\opencode-temp\reach_v65.log', 'r', encoding='utf-8', errors='replace').read()

def grab(tag):
    m = re.search(r'=== bytes: %s \((0x[0-9a-f]+)\) ===(.*?)(?=\n===|\Z)' % tag, log, re.S)
    if not m: return None, None
    n = int(m.group(1), 16)
    body = m.group(2)
    hexs = ''
    for line in body.splitlines():
        mm = re.match(r'\s+\S+\+[0-9a-f]+:\s+([0-9a-f ]+)', line)
        if mm: hexs += mm.group(1).replace(' ', '')
    return n, bytes.fromhex(hexs)

def dis(name, tag, base):
    n, data = grab(tag)
    if data is None:
        print('no data for', tag); return
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    print('=' * 78)
    print('%s  base=0x%x  len=0x%x' % (name, base, len(data)))
    print('=' * 78)
    for i in md.disasm(data, base):
        print('%016x  %-9s %s' % (i.address, i.mnemonic, i.op_str))

dis('set real (IOConnectCallMethod-with-port?)', 'set real', 0x1a219cae0)
dis('remove real (IOConnectCallMethod?)', 'remove real', 0x1a21827cc)

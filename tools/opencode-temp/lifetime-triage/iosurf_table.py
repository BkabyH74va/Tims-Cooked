import sys
sys.path.insert(0, r'G:/REPO\tools\opencode-temp')
from kc import IOSURFACE, macho_sections
import struct

data = IOSURFACE.read_bytes()
secs = macho_sections(data)
const = [s for s in secs if s[0] == '__DATA_CONST' and s[1] == '__const'][0]
seg, sect, caddr, csize, coff = const
BASE = 0xFFFFFE0007000000
tsecs = [s for s in secs if s[0] == '__TEXT_EXEC' and s[1] == '__text'][0]
taddr, tsize = tsecs[2], tsecs[3]

def decoded_target(w):
    return BASE + (w & 0xFFFFFF) + (((w >> 24) & 0xFF) << 24)

STRIDE = 0x28
n_entries = csize // STRIDE

print('Scanning __DATA_CONST.__const at stride 0x28 (%d possible entries)...' % n_entries)
tables = []
entry_start = None
run = 0
for i in range(n_entries):
    off = coff + i * STRIDE
    handler_word = struct.unpack_from('<Q', data, off)[0]
    handler_va = decoded_target(handler_word)
    if taddr <= handler_va < taddr + tsize:
        if entry_start is None:
            entry_start = i
        run += 1
    else:
        if run >= 3:
            tables.append((entry_start, run))
        entry_start = None
        run = 0
if run >= 3:
    tables.append((entry_start, run))

print('Found %d dispatch table regions:' % len(tables))
for start, runlen in tables:
    va = caddr + start * STRIDE
    print('  TABLE @ %018x  selectors=%d' % (va, runlen))
    # Print entries
    for s in range(min(runlen, 8)):
        eoff = coff + (start + s) * STRIDE
        entry = data[eoff:eoff + STRIDE]
        hw = struct.unpack_from('<Q', entry, 0)[0]
        hv = decoded_target(hw)
        sIn = struct.unpack_from('<I', entry, 8)[0]
        stIn = struct.unpack_from('<I', entry, 12)[0]
        sOut = struct.unpack_from('<I', entry, 16)[0]
        stOut = struct.unpack_from('<I', entry, 20)[0]
        flag = 'TEXT' if taddr <= hv < taddr + tsize else '   '
        print('    sel %2d: handler=%018x [%s] sIn=%-6d stIn=%-12d sOut=%-6d stOut=%-6d' % (
            s, hv, flag, sIn, stIn, sOut, stOut))
    if runlen > 8:
        print('    ... (%d more selectors)' % (runlen - 8))

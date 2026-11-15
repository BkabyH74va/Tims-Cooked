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

# Search for sel 0 pattern: sIn=1, stIn=0xFFFFFFFF, sOut=0, stOut=0xC68
# at 8-byte aligned offsets in __DATA_CONST.__const
found = []
for i in range(0, csize - 24, 4):  # scan every 4 bytes for the 4-u32 pattern
    off = coff + i
    sIn = struct.unpack_from('<I', data, off)[0]
    stIn = struct.unpack_from('<I', data, off + 4)[0]
    sOut = struct.unpack_from('<I', data, off + 8)[0]
    stOut = struct.unpack_from('<I', data, off + 12)[0]
    if sIn == 1 and stIn == 0xFFFFFFFF and sOut == 0 and stOut == 0xC68:
        # Check handler pointer 8 bytes before sIn
        handler_off = off - 8
        if handler_off >= coff:
            hw = struct.unpack_from('<Q', data, handler_off)[0]
            hv = decoded_target(hw)
            if taddr <= hv < taddr + tsize:
                entry_va = caddr + (handler_off - coff)
                found.append((entry_va, hv, sIn, stIn, sOut, stOut))

print('Found %d sel-0-style entries:' % len(found))
for entry_va, hv, sIn, stIn, sOut, stOut in found:
    print('  entry @ %018x: handler=%018x sIn=%d stIn=%08x sOut=%d stOut=%08x' % (
        entry_va, hv, sIn, stIn, sOut, stOut))

# Now for each found entry, dump the full table (stride 0x28)
for entry_va, hv, sIn, stIn, sOut, stOut in found:
    entry_sect_off = entry_va - caddr
    print()
    print('=== Full table starting at %018x ===' % entry_va)
    for s in range(60):
        e_sect_off = entry_sect_off + s * 0x28
        if e_sect_off + 0x28 > csize:
            break
        e_off = coff + e_sect_off
        entry = data[e_off:e_off + 0x28]
        hw = struct.unpack_from('<Q', entry, 0)[0]
        hv = decoded_target(hw)
        sIn_v = struct.unpack_from('<I', entry, 8)[0]
        stIn_v = struct.unpack_from('<I', entry, 12)[0]
        sOut_v = struct.unpack_from('<I', entry, 16)[0]
        stOut_v = struct.unpack_from('<I', entry, 20)[0]
        flag = 'TEXT' if taddr <= hv < taddr + tsize else '   '
        print('  sel %2d: handler=%018x [%s] sIn=%-6d stIn=%-12d sOut=%-6d stOut=%-6d' % (
            s, hv, flag, sIn_v, stIn_v, sOut_v, stOut_v))

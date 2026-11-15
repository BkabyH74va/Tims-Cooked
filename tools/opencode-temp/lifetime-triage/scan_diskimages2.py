import sys
sys.path.insert(0, r'G:/REPO\tools\opencode-temp')
from pathlib import Path
import struct

KEXT_PATH = Path(r"G:/REPO\tools\opencode-temp\lifetime-triage\extract\com.apple.driver.AppleDiskImages2")
data = KEXT_PATH.read_bytes()

magic, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IiiIIIII", data, 0)
off = 32
sections = []
for _ in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    if cmd == 0x19:
        name = data[off+8:off+24].rstrip(b"\x00").decode("ascii", "replace")
        vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", data, off+24)
        nsects = struct.unpack_from("<I", data, off+64)[0]
        so = off + 72
        for _ in range(nsects):
            sectname = data[so:so+16].rstrip(b"\x00").decode("ascii", "replace")
            seg = data[so+16:so+32].rstrip(b"\x00").decode("ascii", "replace")
            saddr, ssize = struct.unpack_from("<QQ", data, so+32)
            sfoff = struct.unpack_from("<I", data, so+48)[0]
            sections.append((seg, sectname, saddr, ssize, sfoff))
            so += 80
    off += cmdsize

const_sec = [s for s in sections if s[0] == "__DATA_CONST" and s[1] == "__const"][0]
text_sec = [s for s in sections if s[0] == "__TEXT_EXEC" and s[1] == "__text"][0]
seg, sect, caddr, csize, coff = const_sec
_, _, taddr, tsize, _ = text_sec
BASE = 0xFFFFFE0007000000

def decoded_target(w):
    return BASE + (w & 0xFFFFFF) + (((w >> 24) & 0xFF) << 24)

n = csize // 8
vals = [struct.unpack_from('<Q', data, coff+i*8)[0] for i in range(n)]

for STRIDE in [0x18, 0x20]:
    step = STRIDE // 8
    tables = []
    i = 0
    while i < n - step * 2:
        if not (taddr <= decoded_target(vals[i]) < taddr + tsize):
            i += 1
            continue
        run = 0
        k = i
        while k < n and taddr <= decoded_target(vals[k]) < taddr + tsize:
            base_off = k * 8
            counts_ok = True
            for cpos in range(1, 5):
                if base_off + cpos * 4 >= csize:
                    counts_ok = False
                    break
                c = struct.unpack_from('<I', data, coff + base_off + cpos * 4)[0]
                if c > 0x100000:
                    counts_ok = False
                    break
            if not counts_ok:
                break
            run += 1
            k += step
        if run >= 3:
            tables.append((i, run))
            i = k
        else:
            i += 1
    if tables:
        print(f"Stride {STRIDE:#x}: {len(tables)} tables")
        for start, runlen in tables[:3]:
            va = caddr + start * step * 8
            print(f"  TABLE @ {va:#018x} selectors={runlen}")
            for s in range(min(runlen, 8)):
                eoff = coff + (start + s) * step * 8
                entry = data[eoff:eoff + step * 8]
                hw = struct.unpack_from('<Q', entry, 0)[0]
                hv = decoded_target(hw)
                sIn = struct.unpack_from('<I', entry, 8)[0]
                stIn = struct.unpack_from('<I', entry, 12)[0]
                sOut = struct.unpack_from('<I', entry, 16)[0]
                stOut = struct.unpack_from('<I', entry, 20)[0]
                flag = 'TEXT' if taddr <= hv < taddr + tsize else '   '
                print(f"    sel {s}: handler={hv:#018x} [{flag}] sIn={sIn:#x} stIn={stIn:#x} sOut={sOut:#x} stOut={stOut:#x}")

if not tables:
    print("No dispatch tables found at stride 0x18 or 0x20 — likely switch-based externalMethod")

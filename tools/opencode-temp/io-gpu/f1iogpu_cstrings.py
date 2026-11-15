import struct, sys
sys.path.insert(0, r"G:/REPO\tools\opencode-temp\io-gpu")
from f1iogpu_macho import M

path = sys.argv[1]
m = M(path)
for s in m.segs:
    for i in range(0, 0):
        pass

# collect sections
secs = []
for cmd, cmdsize, o in m.lcs:
    if cmd == 0x19:
        nsects = struct.unpack_from('<I', m.d, o+64)[0]
        so = o + 72
        for i in range(nsects):
            sectname = m.d[so:so+16].split(b'\0')[0].decode('utf8','replace')
            segname = m.d[so+16:so+32].split(b'\0')[0].decode('utf8','replace')
            addr, size, offset = struct.unpack_from('<QQI', m.d, so+32)
            secs.append((sectname, segname, addr, size, offset))
            so += 80

out = []
for sectname, segname, addr, size, offset in secs:
    if sectname not in ('__cstring', '__os_log', '__const'):
        continue
    data = m.d[offset:offset+size]
    start = 0
    for j in range(len(data)):
        if data[j] == 0:
            if j > start:
                out.append((addr+start, data[start:j].decode('utf8','replace')))
            start = j+1
for a, s in out:
    print('0x%x\t%s' % (a, s))

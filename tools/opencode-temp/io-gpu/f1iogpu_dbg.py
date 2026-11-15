import re, sys
DIS = r"G:/REPO\tools\opencode-temp\io-gpu\iosurf.disasm.txt"
lines = open(DIS, encoding='utf-8').read().split('\n')
ins = []
for l in lines:
    l = l.rstrip('\r')
    m = re.match(r'^(0x[0-9a-f]+):\s+([0-9a-f ]+)\s+(\S.*)$', l)
    if m:
        ins.append((int(m.group(1), 16), m.group(3).strip()))
print('ins', len(ins))
idx = {a: k for k, (a, t) in enumerate(ins)}
i = idx[0xfffffe000a32c64c]
for j in range(i-4, i+1):
    print(j, repr(ins[j][1]))
t2 = ins[i-1][1]
mm = re.match(r'^add\s+(x\d+),\s*(x\d+),\s*#(0x[0-9a-f]+)$', t2)
print('mm', mm)

import re, sys, collections

DIS = r"G:/REPO\tools\opencode-temp\io-gpu\iosurf.disasm.txt"
CSTR = r"G:/REPO\tools\opencode-temp\io-gpu\iosurf.cstr.txt"

strings = {}
for line in open(CSTR, encoding='utf-8'):
    if '\t' in line:
        a, s = line.rstrip('\n').lstrip('\ufeff').split('\t', 1)
        strings[int(a, 16)] = s

raw = []
for l in open(DIS, encoding='utf-8').read().split('\n'):
    l = l.rstrip('\r')
    m = re.match(r'^(0x[0-9a-f]+):\s+((?:[0-9a-f]{2} )*[0-9a-f]{2})\s+(\S.*)$', l)
    if m:
        raw.append((int(m.group(1), 16), m.group(3).strip()))

pages = {}
vals = [None] * len(raw)      # computed value for add/adr instructions
movs = [None] * len(raw)

for i, (addr, txt) in enumerate(raw):
    m = re.match(r'^adrp\s+(x\d+),\s*(0x[0-9a-f]+)$', txt)
    if m:
        pages[m.group(1)] = int(m.group(2), 16)
        vals[i] = int(m.group(2), 16)
        continue
    m = re.match(r'^adr\s+(x\d+),\s*(0x[0-9a-f]+)$', txt)
    if m:
        vals[i] = int(m.group(2), 16)
        continue
    m = re.match(r'^add\s+(x\d+),\s*(x\d+),\s*#(0x[0-9a-f]+)$', txt)
    if m and m.group(2) in pages:
        vals[i] = pages[m.group(2)] + int(m.group(3), 16)
        continue
    m = re.match(r'^mov\s+(x\d+),\s*#(0x[0-9a-f]+)$', txt)
    if m:
        movs[i] = int(m.group(2), 16)

targets = sys.argv[1:] or ['0xfffffe000a3308d8']
out = collections.defaultdict(list)
for i, (addr, txt) in enumerate(raw):
    m = re.match(r'^(bl|b)\s+(0x[0-9a-f]+)$', txt)
    if not m or m.group(2) not in targets:
        continue
    found = None
    for j in range(i-1, max(0, i-12), -1):
        t2 = raw[j][1]
        mm = re.match(r'^add\s+(x1),\s*(x\d+),\s*#(0x[0-9a-f]+)$', t2)
        if mm and vals[j] is not None:
            found = vals[j]
            break
        mm = re.match(r'^(?:mov|adr)\s+(x1),\s*(0x[0-9a-f]+)$', t2)
        if mm:
            found = movs[j] if t2.startswith('mov') else vals[j]
            break
    out[m.group(2)].append((addr, found))

for t in targets:
    print('=== calls to %s ===' % t)
    for addr, val in out.get(t, []):
        s = strings.get(val, ('<0x%x>' % val) if val is not None else '?')
        print('  0x%x  x1=0x%x  %s' % (addr, val if val is not None else 0, s))

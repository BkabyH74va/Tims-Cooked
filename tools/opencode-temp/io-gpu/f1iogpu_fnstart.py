import re, sys
from pathlib import Path

path = sys.argv[1]
target = int(sys.argv[2], 0)

raw = Path(path).read_bytes()
if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
    txt = raw.decode("utf-16")
else:
    txt = raw.decode("utf-8", errors="replace")

ADDR = re.compile(r"^0x([0-9a-f]+):")
ins = []
for l in txt.splitlines():
    m = ADDR.match(l)
    if m:
        ins.append((int(m.group(1), 16), l))

start = None
for a, l in ins:
    if a > target:
        break
    if re.search(r'\tbti c$', l) or 'paciasp' in l or 'pacibsp' in l:
        start = a
print("function start guess: 0x%x (target 0x%x)" % (start or 0, target))

# find the next function start after
nxt = None
for a, l in ins:
    if a > (start or 0):
        if re.search(r'\tbti c$', l) or 'paciasp' in l or 'pacibsp' in l:
            nxt = a
            break
print("next function start: 0x%x  size=0x%x" % (nxt or 0, (nxt - start) if (nxt and start) else 0))

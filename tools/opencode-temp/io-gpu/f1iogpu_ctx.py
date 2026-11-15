import re, sys
from pathlib import Path

path = sys.argv[1]
target = int(sys.argv[2], 0)
before = int(sys.argv[3]) if len(sys.argv) > 3 else 40
after = int(sys.argv[4]) if len(sys.argv) > 4 else 120

raw = Path(path).read_bytes()
if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
    txt = raw.decode("utf-16")
else:
    txt = raw.decode("utf-8", errors="replace")

lines = txt.splitlines()
ADDR = re.compile(r"^0x([0-9a-f]+):")
idxs = []
for i, l in enumerate(lines):
    m = ADDR.match(l)
    if m:
        idxs.append((int(m.group(1), 16), i))

pos = None
for k, (a, i) in enumerate(idxs):
    if a == target:
        pos = (k, i)
        break
if pos is None:
    # nearest below
    for k, (a, i) in enumerate(idxs):
        if a <= target:
            pos = (k, i)
    print("(exact not found, showing from nearest below)")
k, i = pos
start = lines[max(0, i-before):i]
end = lines[i:i+after]
for l in start:
    print(l)
print("======= TARGET =======")
for l in end:
    print(l)

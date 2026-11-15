import re
from pathlib import Path
text=Path("iosurface_27_0_1.disasm.txt").read_text(errors="replace").splitlines()
al=[]
for ln in text:
    m=re.match(r"^([0-9a-f]{16})\s+(.*)$",ln)
    if m: al.append((int(m.group(1),16),m.group(2)))
al.sort()
starts=[a for a,t in al if t.strip().startswith("bti")]
print("lines",len(al),"starts",len(starts),"first",hex(starts[0]),"last",hex(starts[-1]))
a=0xa327370
best=None
for f in starts:
    if f<=a: best=f
    else: break
print("fstart",hex(best) if best else None)
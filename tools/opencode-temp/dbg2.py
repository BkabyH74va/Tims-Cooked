import re,sys
from pathlib import Path
lines=Path("iosurface_27_0_1.disasm.txt").read_text(errors="replace").splitlines()
ins={}
for ln in lines:
    m=re.match(r"^([0-9a-f]{16})\s+(.*)$",ln)
    if m: ins[int(m.group(1),16)]=m.group(2).strip()
fn=0xfffffe000a34c7cc
n=0
for a in range(fn, fn+0x300, 4):
    t=ins.get(a)
    if t is None: continue
    if "adrp" in t:
        m=re.match(r"adrp\s+(x\d+), #0x([0-9a-f]+)",t)
        print(hex(a), repr(t), "->", m.groups() if m else "NO MATCH")
        n+=1
        if n>4: break
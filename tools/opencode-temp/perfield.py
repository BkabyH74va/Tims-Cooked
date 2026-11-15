import re
from pathlib import Path
lines=Path("iosurface_27_0_1.disasm.txt").read_text(errors="replace").splitlines()
ins={}
for ln in lines:
    m=re.match(r"^([0-9a-f]{16})\s+(.*)$",ln)
    if m: ins[int(m.group(1),16)]=m.group(2).strip()
starts=sorted(a for a,t in ins.items() if t.startswith("bti"))
def fstart(a):
    best=None
    for f in starts:
        if f<=a: best=f
        else: break
    return best
# find reads/writes of +0x34 / +0x38 (the per-slice fields) outside the parser
hits={}
for a in sorted(ins):
    t=ins[a]
    m=re.search(r"\[(x\d+), #0x(34|38)\]",t)
    if m:
        fn=fstart(a)
        hits.setdefault(fn,[]).append((a,t.strip()))
for fn,v in sorted(hits.items()):
    if len(v)>=2:
        print("fn 0x%x  (%d refs)"%(fn,len(v)))
        for a,t in v[:6]:
            print("    0x%x  %s"%(a,t))
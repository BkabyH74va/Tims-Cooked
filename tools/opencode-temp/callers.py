import re,sys
from pathlib import Path
text=Path("iosurface_27_0_1.disasm.txt").read_text(errors="replace").splitlines()
al=[]
for ln in text:
    m=re.match(r"^([0-9a-f]{16})\s+(.*)$",ln)
    if m: al.append((int(m.group(1),16),m.group(2)))
al.sort()
starts=[a for a,t in al if t.strip().startswith("bti")]
def fstart(a):
    best=None
    for f in starts:
        if f<=a: best=f
        else: break
    return best
for tgt in [0xfffffe0000000000 | int(x,0) for x in sys.argv[1:]]:
    fs=fstart(tgt)
    print("target 0x%x in function 0x%x"%(tgt,fs))
    if fs is None: continue
    for a,t in al:
        m=re.search(r"bl\s+#0x([0-9a-f]{16})",t)
        if m and int(m.group(1),16)==fs:
            print("   called from 0x%x (fn 0x%x)"%(a,fstart(a)))
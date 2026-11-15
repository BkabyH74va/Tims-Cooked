import re
from pathlib import Path
lines=Path("iosurface_27_0_1.disasm.txt").read_text(errors="replace").splitlines()
out=[]
for ln in lines:
    m=re.match(r"^([0-9a-f]{16})\s+(.*)$",ln)
    if not m: continue
    a=int(m.group(1),16)
    if 0xfffffe000a32b7b4 <= a < 0xfffffe000a32d200:
        t=m.group(2).strip()
        if re.search(r"\bx26\b", t):
            out.append("0x%x  %s"%(a,t))
print("\n".join(out[:30]))
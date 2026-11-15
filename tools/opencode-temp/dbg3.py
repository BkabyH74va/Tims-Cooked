import re,sys
from pathlib import Path
sys.path.insert(0,".")
from kc_iosurface import parse_fileset, member_segments
data=Path("../../firmware/24A446/kernelcache.release.macho").read_bytes()
entries,_=parse_fileset(data)
e=[x for x in entries if x["name"]=="com.apple.iokit.IOSurface"][0]
segs=member_segments(data,e["fileoff"])
print("segments:")
for s,(vm,vms,fo,fs) in segs.items():
    print("  %-14s vm=0x%x size=0x%x fo=0x%x fs=0x%x"%(s,vm,vms,fo,fs))
lines=Path("iosurface_27_0_1.disasm.txt").read_text(errors="replace").splitlines()
ins={}
for ln in lines:
    m=re.match(r"^([0-9a-f]{16})\s+(.*)$",ln)
    if m: ins[int(m.group(1),16)]=m.group(2).strip()
for a in range(0xfffffe000a34c800,0xfffffe000a34c830,4):
    print(hex(a), ins.get(a))
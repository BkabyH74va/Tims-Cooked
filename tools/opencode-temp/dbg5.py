import re,sys
from pathlib import Path
sys.path.insert(0,".")
from kc_iosurface import parse_fileset, member_segments
data=Path("../../firmware/24A446/kernelcache.release.macho").read_bytes()
entries,_=parse_fileset(data)
e=[x for x in entries if x["name"]=="com.apple.iokit.IOSurface"][0]
segs=member_segments(data,e["fileoff"])
memb=[(s,vm,fo,fs) for s,(vm,vms,fo,fs) in segs.items() if fs]
def cstr(vm):
    for s,svm,fo,fs in memb:
        if svm<=vm<svm+fs:
            off=fo+(vm-svm); end=data.find(b"\x00",off,off+400)
            if end<0: return None
            try: return data[off:end].decode("ascii")
            except Exception: return None
    return None
ins={}
for ln in Path("iosurface_27_0_1.disasm.txt").read_text(errors="replace").splitlines():
    m=re.match(r"^([0-9a-f]{16})\s+(.*)$",ln)
    if m: ins[int(m.group(1),16)]=m.group(2).strip()
fn=0xfffffe000a34c7cc
page=None
for a in range(fn,fn+0x120,4):
    t=ins.get(a)
    if t is None:
        continue
    m=re.match(r"adrp\s+(x\d+), #0x([0-9a-f]+)",t)
    if m:
        page=int(m.group(2),16); continue
    m=re.match(r"add\s+(x\d+), (x\d+), #0x([0-9a-f]+)",t)
    if m and page is not None:
        vm=page+int(m.group(3),16)
        s=cstr(vm) if 0xfffffe0007a180000<=vm<0xfffffe0007a200000 else None
        print(hex(a), t, "-> vm=0x%x"%vm, "str=",s)
        page=None
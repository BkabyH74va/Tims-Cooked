import re,struct,sys
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
            except: return None
    return None
lines=Path("iosurface_27_0_1.disasm.txt").read_text(errors="replace").splitlines()
ins={}
for ln in lines:
    m=re.match(r"^([0-9a-f]{16})\s+(.*)$",ln)
    if m: ins[int(m.group(1),16)]=m.group(2).strip()
starts=sorted(a for a,t in ins.items() if t.startswith("bti"))
def fn_end(a):
    for f in starts:
        if f>a: return f
    return a+0x1000
def names(fn, win=0x600):
    out=[]; page=None
    end=fn_end(fn)
    for a in range(fn,min(end,fn+win),4):
        t=ins.get(a)
        if not t: continue
        m=re.match(r"adrp\s+(x\d+), #0x([0-9a-f]+)",t)
        if m: page=int(m.group(2),16); continue
        m=re.match(r"add\s+(x\d+), (x\d+), #0x([0-9a-f]+)",t)
        if m and page is not None:
            vm=page+int(m.group(3),16)
            if 0xfffffe0007a180000<=vm<0xfffffe0007a200000:
                s=cstr(vm)
                if s and len(s)>3 and s.isprintable() and s not in out: out.append(s)
            page=None
    return out
base=segs["__DATA_CONST"][2]+0x2638
for i in range(0x3c):
    q=struct.unpack_from("<Q",data[base+i*40:base+i*40+40])[0]
    plain=q&0x0000FFFFFFFFFFFF; low=q&0xFFFFFFFF
    h=None
    if 0xfffffe000a325000<=plain<0xfffffe000a360000: h=plain
    if h is None:
        for s,svm,fo,fs in memb:
            if fo<=low<fo+fs:
                r=svm+(low-fo)
                if 0xfffffe000a325000<=r<0xfffffe000a360000: h=r
    if h is None: continue
    # follow thunk
    fn=h
    for k in range(8):
        t=ins.get(fn+k*4)
        if not t: break
        m=re.match(r"b\s+#0x([0-9a-f]{16})",t)
        if m: fn=int(m.group(1),16); break
    nm=[s for s in names(fn) if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$",s)]
    print("0x%02x fn=0x%x  %s"%(i,fn,"; ".join(nm[:4]) if nm else "-"))
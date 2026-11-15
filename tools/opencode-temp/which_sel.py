import re,struct,sys
from pathlib import Path
sys.path.insert(0,".")
from kc_iosurface import parse_fileset, member_segments
text=Path("iosurface_27_0_1.disasm.txt").read_text(errors="replace").splitlines()
al=[]
for ln in text:
    m=re.match(r"^([0-9a-f]{16})\s+(.*)$",ln)
    if m: al.append((int(m.group(1),16),m.group(2)))
al.sort()
starts=[a for a,t in al if t.startswith("bti")]
def fend(a):
    for f in starts:
        if f>a: return f
    return a+0x1000
data=Path("../../firmware/24A446/kernelcache.release.macho").read_bytes()
entries,_=parse_fileset(data)
e=[x for x in entries if x["name"]=="com.apple.iokit.IOSurface"][0]
segs=member_segments(data,e["fileoff"])
memb=[(s,vm,fo,fs) for s,(vm,vms,fo,fs) in segs.items() if fs]
tex=segs.get("__TEXT_EXEC") or segs["__TEXT"]
def fo2vm(f):
    for s,vm,fo,fs in memb:
        if fo<=f<fo+fs: return vm+(f-fo)
dcvm,dcvms,dcfo,dcfs=segs["__DATA_CONST"]
base=dcfo+0x2638
byaddr={a:t for a,t in al}
def thunk(h):
    for i in range(8):
        t=byaddr.get(h+i*4)
        if t is None: return None
        m=re.match(r"b\s+#0x([0-9a-f]{16})",t)
        if m: return int(m.group(1),16)
    return None
targets=[int(x,0) for x in sys.argv[1:]]
for i in range(0x3C):
    q=struct.unpack_from("<Q",data[base+i*40:base+i*40+40])[0]
    low=q&0xFFFFFFFF; plain=q&0x0000FFFFFFFFFFFF; h=None
    if tex[0]<=plain<tex[0]+tex[1]: h=plain
    elif low:
        r=fo2vm(low)
        if r is not None and tex[0]<=r<tex[0]+tex[1]: h=r
    if h is None: continue
    fn=thunk(h) or h
    end=fend(fn)
    for t in targets:
        if fn<=t<end:
            print("target 0x%x is inside selector 0x%02x function 0x%x..0x%x"%(t,i,fn,end))
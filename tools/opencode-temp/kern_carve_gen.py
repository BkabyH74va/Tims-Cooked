import sys, struct, bisect
sys.path.insert(0,"tools/opencode-temp"); sys.path.insert(0,"tools/pylibs")
from kc_iosurface import parse_fileset, member_segments, member_load_commands
data=open("firmware/24A446/kernelcache.release.macho","rb").read()
entries,_=parse_fileset(data)
def fstarts(foff,text_base):
    out=[]
    for cmd,eoff,cmdsize in member_load_commands(data,foff):
        if cmd!=0x26: continue
        dataoff=struct.unpack_from("<I",data,eoff+8)[0]; size=struct.unpack_from("<I",data,eoff+12)[0]
        p,end=dataoff,dataoff+size; addr=0
        while p<end:
            val=0;shift=0
            while True:
                b=data[p];p+=1;val|=(b&0x7F)<<shift
                if not (b&0x80):break
                shift+=7
            if val==0: break
            addr+=val; out.append(text_base+addr)
    return sorted(set(out))
for e in entries:
    if e["name"]!="com.apple.kernel": continue
    segs=member_segments(data,e["fileoff"])
    vm,vsz,fo,fsz=segs["__TEXT"]
    starts=fstarts(e["fileoff"],vm)
    targets=[0xfffffe00070689cc,0xfffffe00070697d6,0xfffffe000706a263]
    blob=data[fo:fo+fsz]
    pages={}
    found={t:[] for t in targets}
    for i in range(0,len(blob)-3,4):
        w=struct.unpack_from('<I',blob,i)[0]
        va=vm+i
        if (w & 0x9F000000)==0x90000000:
            rd=w&0x1F; immlo=(w>>29)&3; immhi=(w>>5)&0x7FFFF
            imm=(immhi<<2)|immlo
            if imm&(1<<20): imm-=1<<21
            pages[rd]=(va+imm*4096)&((1<<64)-1)
        elif (w & 0xFF800000)==0x91000000:
            rn=(w>>5)&0x1F; imm=(w>>10)&0xFFF; sh=12 if (w&0x400000) else 0
            if rn in pages:
                tgt=(pages[rn]+(imm<<sh))&((1<<64)-1)
                if tgt in found: found[tgt].append(va)
        elif (w & 0xFFC00000)==0xF9400000:
            rn=(w>>5)&0x1F; rt=w&0x1F; imm=((w>>10)&0xFFF)*8
            if rn in pages:
                tgt=(pages[rn]+imm)&((1<<64)-1)
                if tgt in found: found[tgt].append(va)
            pages.pop(rt,None)
    for t in targets:
        print("target",hex(t),"refs",len(found[t]))
        for s in found[t]:
            j=bisect.bisect_right(starts,s)-1
            fn=starts[j] if j>=0 else None
            print(f"   ref at {hex(s)} func {hex(fn) if fn else '?'}")

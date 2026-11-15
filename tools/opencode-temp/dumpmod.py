import struct,sys
def sections(path):
    d=open(path,"rb").read(); magic,_,_,_,ncmds,_,_,_=struct.unpack_from("<IiiIIIII",d,0)
    off=32; out=[]
    for _ in range(ncmds):
        cmd,cmdsize=struct.unpack_from("<II",d,off)
        if cmd==0x19:
            seg=d[off+8:off+24].rstrip(b"\0").decode(); nsects=struct.unpack_from("<I",d,off+64)[0]; so=off+72
            for _ in range(nsects):
                sn=d[so:so+16].rstrip(b"\0").decode(); addr,size=struct.unpack_from("<QQ",d,so+32); fo=struct.unpack_from("<I",d,so+48)[0]
                out.append((seg,sn,addr,size,fo)); so+=80
        off+=cmdsize
    return d,out
base=0xfffffe0007000000
for lab,path in [("2701",r"G:/REPO\analysis\agx\2701\com.apple.AGXG18P"),("272",r"G:/REPO\analysis\agx\272\com.apple.AGXG18P")]:
    d,secs=sections(path)
    starts=set(int(x,16) for x in open(r"G:/REPO\tools\opencode-temp\starts"+lab+".txt",encoding="utf-16"))
    print("====",lab,"base",hex(base))
    for seg,sn,addr,size,fo in secs:
        if sn in ("__mod_init_func","__mod_term_func"):
            print("--",sn,"count",size//8)
            for i in range(size//8):
                v=struct.unpack_from("<Q",d,fo+i*8)[0]
                t=base+(v&0xffffffff)
                print(hex(addr+i*8),hex(v),"->",hex(t),"start" if t in starts else "NOTSTART")


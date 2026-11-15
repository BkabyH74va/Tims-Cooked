import struct,bisect
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
for lab,path in [("2701",r"G:/REPO\analysis\agx\2701\com.apple.AGXG18P")]:
    d,secs=sections(path)
    starts=sorted(int(x,16) for x in open(r"G:/REPO\tools\opencode-temp\starts"+lab+".txt",encoding="utf-16"))
    print("text first/last",hex(starts[0]),hex(starts[-1]))
    for seg,sn,addr,size,fo in secs:
        if sn=="__mod_init_func":
            for i in range(min(size//8,25)):
                v=struct.unpack_from("<Q",d,fo+i*8)[0]; t=base+(v&0xffffffff)
                j=bisect.bisect_left(starts,t)
                near=min(starts[max(0,j-1):j+2], key=lambda s:abs(s-t))
                print(hex(t),"nearest start",hex(near),"delta",t-near)

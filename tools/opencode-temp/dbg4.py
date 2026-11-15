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
            print("   segment",s,"off=0x%x"%off,"bytes:",data[off:off+40])
            if end<0: return None
            return data[off:end].decode("ascii","replace")
    print("   not in any segment")
    return None
print(cstr(0xfffffe0007a1b86e))
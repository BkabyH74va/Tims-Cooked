import sys
from pathlib import Path
sys.path.insert(0,".")
from kc_iosurface import parse_fileset, member_segments
data=Path("../../firmware/24A446/kernelcache.release.macho").read_bytes()
entries,_=parse_fileset(data)
e=[x for x in entries if x["name"]=="com.apple.iokit.IOSurface"][0]
segs=member_segments(data,e["fileoff"])
memb=[(s,vm,fo,fs) for s,(vm,vms,fo,fs) in segs.items() if fs]
def raw(vm,n=64):
    for s,svm,fo,fs in memb:
        if svm<=vm<svm+fs:
            off=fo+(vm-svm); return data[off:off+n]
    return b""
for vm in (0xfffffe0007a1906be,0xfffffe0007a190702,0xfffffe0007a190711,0xfffffe0007a19075e,0xfffffe0007a190773,0xfffffe0007a190894,0xfffffe0007a1906e9):
    b=raw(vm)
    print(hex(vm), b[:48])
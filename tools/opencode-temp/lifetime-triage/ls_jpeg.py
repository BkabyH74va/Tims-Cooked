import kx

m = kx.MachO(kx.EXTRACT / "com.apple.driver.AppleJPEGDriver")
for s in m.sections:
    if s["size"] > 0:
        print(f"{s['seg']}.{s['sect']}\taddr={s['addr']:#018x}\tsize={s['size']:#x}\toffset={s['offset']:#x}")
print("=== load commands ===")
for l in m.loadcmds:
    print(l)

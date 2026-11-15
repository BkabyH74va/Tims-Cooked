import re
from pathlib import Path

p = Path("ContentView-v122.swift")
t = p.read_text()

old = """        // ---- 3. wrap the backing in an MTLBuffer ---------------------------
        guard let kp = UnsafeMutableRawPointer(bitPattern: Int(truncatingIfNeeded: kbase)) else { emit("[-] bad kbase"); return }"""
new = """        // ---- 3. wrap the backing in an MTLBuffer ---------------------------
        // (IOSurfaceLookup gives us the IOSurfaceRef for the texture path)
        typealias LookupFn4 = @convention(c) (UInt32) -> UnsafeMutableRawPointer?
        var lookupFn: LookupFn4? = nil
        if let fw = dlopen("/System/Library/Frameworks/IOSurface.framework/IOSurface", RTLD_NOW),
           let lu = dlsym(fw, "IOSurfaceLookup") {
            lookupFn = unsafeBitCast(lu, to: LookupFn4.self)
        }
        guard let kp = UnsafeMutableRawPointer(bitPattern: Int(truncatingIfNeeded: kbase)) else { emit("[-] bad kbase"); return }"""
assert old in t
t = t.replace(old, new)
p.write_text(t)
print("patched: IOSurfaceLookup binding")

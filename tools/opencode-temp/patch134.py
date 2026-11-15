import re
from pathlib import Path

p = Path("ContentView-v122.swift")
t = p.read_text()

old = """        var hist3: [String: Int] = [:]
        var ok3: [String] = []
        for count in 0...64 {
            var words: [UInt64] = [UInt64(count),
                                   512,          // IOSurfaceBytesPerRow
                                   64,           // IOSurfaceWidth
                                   64,           // IOSurfaceHeight
                                   0x42475241,   // IOSurfacePixelFormat (ARGB)
                                   0x10000,      // IOSurfaceAllocSize
                                   0,            // IOSurfaceAddress
                                   0]"""
new = """        var hist3: [String: Int] = [:]
        var ok3: [String] = []
        // a real 0x40-byte userspace buffer: the handler loads the first u64
        // of the structure, and if it is non-NULL it allocates 0x40 bytes and
        // calls into the object with the "IOSurfaceAddress" key
        var backing = [UInt8](repeating: 0xAB, count: 0x40)
        let backingAddr = UInt64(UInt(bitPattern: UnsafeMutableRawPointer.allocate(byteCount: 0x40, alignment: 8).assumingMemoryBound(to: UInt8.self)))
        backing.withUnsafeMutableBytes { dst in
            dst.copyMemory(from: UnsafeRawPointer(backingAddr))
        }
        for count in 0...64 {
            var words: [UInt64] = [backingAddr,
                                   512,          // IOSurfaceBytesPerRow
                                   64,           // IOSurfaceWidth
                                   64,           // IOSurfaceHeight
                                   0x42475241,   // IOSurfacePixelFormat (ARGB)
                                   0x10000,      // IOSurfaceAllocSize
                                   0,            // IOSurfaceAddress
                                   0]"""
assert old in t
t = t.replace(old, new)
p.write_text(t)
print("patched: 0x06 with a real user pointer")

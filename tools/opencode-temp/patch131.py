import re
from pathlib import Path

p = Path("ContentView-v122.swift")
t = p.read_text()

# per-selector: scalar input count and structure input size, from the decoded
# IOSurfaceRootUserClient dispatch table (scalarIn, structInSize)
old = """    // selectors whose structure input size is variable or large
    let sels: [UInt32] = [0x02, 0x03, 0x04, 0x06, 0x07, 0x09, 0x0a, 0x0b,
                          0x13, 0x18, 0x1a, 0x1b, 0x1c, 0x1e, 0x22, 0x2e, 0x2f,
                          0x30, 0x31, 0x32, 0x33, 0x36]
    let sizes: [Int] = [0, 8, 16, 32, 64, 88, 160, 256, 0x1000, 0xc68]"""
new = """    // (selector, scalarInputCount, structureInputSize) straight from the
    // decoded dispatch table: 0xffffffff means "variable"
    let shapes: [(UInt32, Int, Int)] = [
        (0x02, 0, 12), (0x03, 0, 12), (0x04, 1, 0), (0x06, 0, 32), (0x07, 2, 0),
        (0x09, 0, -1), (0x0a, 0, -1), (0x0b, 0, -1), (0x13, 0, -1), (0x18, 0, -1),
        (0x1a, 0, -1), (0x1b, 0, 160), (0x1c, 1, 0), (0x1e, 1, -1), (0x22, 1, 0),
        (0x2e, 0, -1), (0x2f, 1, -1), (0x30, 1, -1), (0x31, 1, -1), (0x32, 2, -1),
        (0x33, 2, -1), (0x36, 0, -1)
    ]
    let sizes: [Int] = [0, 8, 16, 32, 64, 88, 160, 256, 0x1000, 0xc68]"""
assert old in t
t = t.replace(old, new)

old2 = """    for sel in sels {
        for size in sizes {
            for (pname, fill) in pats {"""
new2 = """    for (sel, nScalars, fixedSize) in shapes {
      for size in sizes {
        if fixedSize >= 0 && size != fixedSize { continue }
        for (pname, fill) in pats {"""
assert old2 in t
t = t.replace(old2, new2)

old3 = """                var sc: [UInt64] = [0, 0]
                let r: Int32 = sc.withUnsafeMutableBufferPointer { sb in
                    buf.withUnsafeBufferPointer { pb in
                        out.withUnsafeMutableBytes { ob in
                            callMethod(conn, sel, UnsafePointer(sb.baseAddress), 2,
                                       pb.baseAddress, size,
                                       ob.baseAddress, &outSize)
                        }
                    }
                }"""
new3 = """                var sc: [UInt64] = [UInt64](repeating: 0, count: max(nScalars, 1))
                let r: Int32 = sc.withUnsafeMutableBufferPointer { sb in
                    buf.withUnsafeBufferPointer { pb in
                        out.withUnsafeMutableBytes { ob in
                            callMethod(conn, sel, nScalars > 0 ? UnsafePointer(sb.baseAddress) : nil,
                                       UInt32(nScalars),
                                       pb.baseAddress, size,
                                       ob.baseAddress, &outSize)
                        }
                    }
                }"""
assert old3 in t
t = t.replace(old3, new3)

old4 = """                if r == 0 {
                    emit("   ^^^ OK  outSize=0x\\(String(outSize, radix: 16)) desc=\\(out.prefix(0x20).map { String(format: "%02x", $0) }.joined())")
                }
            }
        }
    }"""
new4 = """                if r == 0 {
                    emit("   ^^^ OK  outSize=0x\\(String(outSize, radix: 16)) desc=\\(out.prefix(0x20).map { String(format: "%02x", $0) }.joined())")
                }
            }
        }
      }
    }"""
assert old4 in t
t = t.replace(old4, new4)

p.write_text(t)
print("patched: correct per-selector shapes")

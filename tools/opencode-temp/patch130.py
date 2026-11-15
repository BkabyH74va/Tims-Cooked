import re
from pathlib import Path

p = Path("ContentView-v122.swift")
t = p.read_text()

fuzz = '''
// ---- fuzz the IOSurfaceRoot methods that take a caller-sized structure ----
// The memory-pool / descriptor family (IOSurfaceDescriptorContext,
// IOSurfaceDescriptorComponent, IOSurfaceMemoryPoolBunch, "client shared")
// is the newest and least audited part of the kext and every one of those
// methods takes a caller-sized structure.  This sweeps them with hostile
// lengths and contents and records every return code, so a length-handling
// bug shows up either as an odd rc or as a kernel fault.
func runFuzzMode() async {
    isRunning = true; status = "Fuzzing..."; log = ""
    quietUI = true
    raceBuf = ""
    try? "".write(to: logFileURL, atomically: true, encoding: .utf8)

    var iter: io_iterator_t = 0
    let kr = xq_IOServiceGetMatchingServices(0, xq_IOServiceMatching("IOSurfaceRoot"), &iter)
    guard kr == 0 else { emit("[-] no IOSurfaceRoot"); status = "Complete"; isRunning = false; return }
    let svc = xq_IOIteratorNext(iter)
    var conn: io_connect_t = 0
    guard xq_IOServiceOpen(svc, mach_task_self(), 0, &conn) == 0, conn != 0 else {
        emit("[-] open failed"); status = "Complete"; isRunning = false; return
    }

    // selectors whose structure input size is variable or large
    let sels: [UInt32] = [0x02, 0x03, 0x04, 0x06, 0x07, 0x09, 0x0a, 0x0b,
                          0x13, 0x18, 0x1a, 0x1b, 0x1c, 0x1e, 0x22, 0x2e, 0x2f,
                          0x30, 0x31, 0x32, 0x33, 0x36]
    let sizes: [Int] = [0, 8, 16, 32, 64, 88, 160, 256, 0x1000, 0xc68]
    let pats: [(String, UInt64)] = [("zeros", 0), ("ones", 0xffffffffffffffff),
                                   ("41", 0x4141414141414141),
                                   ("big", 0x7fffffffffffffff),
                                   ("off", 0x0000100000000000)]

    for sel in sels {
        for size in sizes {
            for (pname, fill) in pats {
                var buf = [UInt8](repeating: 0, count: max(size, 8))
                for i in stride(from: 0, to: buf.count, by: 8) {
                    for b in 0..<8 { buf[i + b] = UInt8((fill >> (8 * UInt64(b))) & 0xff) }
                }
                var out = [UInt8](repeating: 0, count: 0xc68)
                var outSize: UInt64 = 0xc68
                var sc: [UInt64] = [0, 0]
                let r: Int32 = sc.withUnsafeMutableBufferPointer { sb in
                    buf.withUnsafeBufferPointer { pb in
                        out.withUnsafeMutableBytes { ob in
                            callMethod(conn, sel, UnsafePointer(sb.baseAddress), 2,
                                       pb.baseAddress, size,
                                       ob.baseAddress, &outSize)
                        }
                    }
                }
                let tag = "sel0x\\(String(sel, radix: 16)) size=0x\\(String(size, radix: 16)) \\(pname) -> \\(krN(r))"
                emitRace(tag)
                if r == 0 {
                    emitRace("   ^^^ OK  outSize=0x\\(String(outSize, radix: 16)) desc=\\(out.prefix(0x20).map { String(format: "%02x", $0) }.joined())")
                }
            }
        }
    }
    emitRace("=== fuzz sweep complete ===")
    _ = xq_IOServiceClose(conn)
    status = "Complete"; isRunning = false
}
'''

anchor = "    // ---- the Metal half -----------------------------------------------------"
assert anchor in t
t = t.replace(anchor, fuzz + "\n" + anchor)

old = """        if args.contains("--metal") { await runMetalMode(); return }"""
new = """        if args.contains("--metal") { await runMetalMode(); return }
        if args.contains("--fuzz") { await runFuzzMode(); return }"""
assert old in t
t = t.replace(old, new)

p.write_text(t)
print("patched: --fuzz mode")

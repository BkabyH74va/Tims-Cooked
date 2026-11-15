import re
from pathlib import Path

p = Path("brotlirepro.swift")
t = p.read_text()

old = """    let d1 = BrotliRepro.stage1()
    let d2 = BrotliRepro.stage2()"""
new = """    // parameter overrides so we can sweep the aim of the wild copy:
    //   --cmdcount=<log2>  size of stage 1 (2^n commands)
    //   --b7=<n>           block-switch bits that corrupt the output position
    //   --d15/--d19/--d23   distance codes (the copy length / source)
    var cmdLog2 = 24
    var b7v: UInt8 = 8
    var d15v: UInt32 = 0x7fffffff
    var d19v: UInt32 = 0x7fffffff
    var d23v: UInt32 = 0x7fffffff
    for a in CommandLine.arguments {
        func val(_ k: String) -> String? {
            guard a.hasPrefix(k + "=") else { return nil }
            return String(a.dropFirst(k.count + 1))
        }
        if let v = val("--cmdcount") { cmdLog2 = Int(v) ?? 24 }
        if let v = val("--b7") { b7v = UInt8(UInt32(v) ?? 8) }
        if let v = val("--d15") { d15v = UInt32(v, radix: 16) ?? 0x7fffffff }
        if let v = val("--d19") { d19v = UInt32(v, radix: 16) ?? 0x7fffffff }
        if let v = val("--d23") { d23v = UInt32(v, radix: 16) ?? 0x7fffffff }
    }
    let d1 = BrotliRepro.stage1(cmdcountLog2: cmdLog2)
    let d2 = BrotliRepro.stage2(d15: d15v, d19: d19v, d23: d23v, b7: b7v)
    try? Data(d1 + d2).write(to: URL(fileURLWithPath: "/tmp/trigger"))"""
assert old in t
t = t.replace(old, new)
p.write_text(t)
print("patched brotlirepro CLI with parameter overrides")

import re
from pathlib import Path

p = Path("ContentView-v122.swift")
t = p.read_text()

old = """        emit("F1 surface created id=\\(sid) kbase=0x\\(String(kbase, radix: 16)) alloc=0x\\(String(u64(0x20), radix: 16))")"""
new = """        emit("F1 surface created id=\\(sid) kbase=0x\\(String(kbase, radix: 16)) alloc=0x\\(String(u64(0x20), radix: 16))")
        // full descriptor dump: the plane area is where the per-slice values live
        var dump = ""
        for o in stride(from: 0x40, to: 0xc8, by: 8) {
            dump += String(format: " %02x:%016x", o, u64(o))
        }
        emit("desc[0x40..0xc8]\(dump)")
        var hits = ""
        for o in stride(from: 0, to: 0xc8 - 8, by: 8) {
            let v = u64(o)
            if v == 0x40000000 || v == 0x4000 || v == 0x10000 {
                hits += " [0x\\(String(o, radix: 16))=0x\\(String(v, radix: 16))]"
            }
        }
        emit("descriptor occurrences of the per-slice values:\(hits.isEmpty ? " NONE" : hits)")"""
assert old in t
t = t.replace(old, new)
p.write_text(t)
print("patched: descriptor dump")

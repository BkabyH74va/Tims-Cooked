import re
from pathlib import Path

p = Path("ContentView-v122.swift")
t = p.read_text()

old = """        var lib: MTLLibrary? = nil
        do {
            lib = try device.makeLibrary(URL: libURL)
        } catch {
            emit("[-] library load failed: \\(error)")
        }
        guard let lib = lib else {
            status = "Complete"; isRunning = false; return
        }
        emit("library loaded from file")"""
new = """        var lib: MTLLibrary? = device.makeDefaultLibrary()
        if lib == nil {
            do {
                lib = try device.makeLibrary(URL: libURL)
            } catch {
                emit("[-] library load failed: \\(error)")
            }
        }
        guard let lib = lib else {
            emit("[-] no Metal library")
            status = "Complete"; isRunning = false; return
        }
        emit("library loaded")"""
assert old in t, "library block not found"
t = t.replace(old, new)
p.write_text(t)
print("app patched to use the bundled default.metallib")

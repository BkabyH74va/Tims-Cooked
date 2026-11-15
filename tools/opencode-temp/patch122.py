import re
from pathlib import Path

p = Path("ContentView-v122.swift")
t = p.read_text()

b64 = Path("default14.metallib.b64").read_text().strip()
t = re.sub(r'let metallibBase64 = "[A-Za-z0-9+/=]+"',
           'let metallibBase64 = "' + b64 + '"', t)

old = """        guard let lib = try? device.makeLibrary(URL: libURL) else {
            emit("[-] library load failed")
            status = "Complete"; isRunning = false; return
        }"""
new = """        var lib: MTLLibrary? = nil
        do {
            lib = try device.makeLibrary(URL: libURL)
        } catch {
            emit("[-] library load failed: \\(error)")
        }
        guard let lib = lib else {
            status = "Complete"; isRunning = false; return
        }"""
assert old in t, "pattern not found"
t = t.replace(old, new)
p.write_text(t)
print("patched, b64 len", len(b64))

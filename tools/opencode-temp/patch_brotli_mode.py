#!/usr/bin/env python3
"""Patch AGXProbe ContentView.swift to add a --brotli mode, install brotlirepro.swift."""
import os, sys

p = os.path.expanduser("~/agx-probe-project/AGXProbe/ContentView.swift")
src = open(p, "r", encoding="utf-8").read()

anchor = """        didAutoRun = true
        if ProcessInfo.processInfo.arguments.contains("--autorun") { await runProbe() }"""

new = """        didAutoRun = true
        if ProcessInfo.processInfo.arguments.contains("--brotli") {
            emit("[br] CVE-2026-111497 repro, iOS " + ProcessInfo.processInfo.operatingSystemVersionString)
            let rc = BrotliRepro.run { self.emit($0) }
            emit("[br] rc=\\(rc)")
            return
        }
        if ProcessInfo.processInfo.arguments.contains("--autorun") { await runProbe() }"""

n = src.count(anchor)
print("anchor occurrences:", n)
if n != 1:
    print("REFUSING: expected exactly 1")
    sys.exit(1)

src = src.replace(anchor, new)
open(p, "w", encoding="utf-8").write(src)
print("patched ContentView.swift")

# install the harness next to it (synchronized root group picks it up)
h = os.path.expanduser("~/agx-probe-project/AGXProbe/brotlirepro.swift")
print("harness present:", os.path.exists(h), os.path.getsize(h) if os.path.exists(h) else 0)

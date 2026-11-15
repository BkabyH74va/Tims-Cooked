#!/usr/bin/env python3
"""Let Xcode compile probe.metal into the app's default.metallib.

- adds metal/probe.metal to the target's Sources build phase
- removes the hand-added default.metallib resource entry (Xcode produces it)
"""
import shutil
import sys
from pathlib import Path

proj = Path.home() / "agx-probe-project"
pbx = proj / "AGXProbe.xcodeproj" / "project.pbxproj"

shutil.copy(pbx, pbx.with_suffix(".pbxproj.bak3"))
t = pbx.read_text()

METAL_REF = "A10000000000000000000030"
METAL_BUILD = "A10000000000000000000031"

if METAL_REF in t:
    print("already patched")
    sys.exit(0)

# 1. file reference
anchor = "/* End PBXFileReference section */"
ref = (
    "\t\t%s /* probe.metal */ = {isa = PBXFileReference; lastKnownFileType = "
    "sourcecode.metal; path = metal/probe.metal; sourceTree = SOURCE_ROOT; };\n"
    % METAL_REF
)
assert anchor in t
t = t.replace(anchor, ref + anchor, 1)

# 2. build file
anchor = "/* End PBXBuildFile section */"
bf = (
    "\t\t%s /* probe.metal in Sources */ = {isa = PBXBuildFile; fileRef = "
    "%s /* probe.metal */; };\n" % (METAL_BUILD, METAL_REF)
)
assert anchor in t
t = t.replace(anchor, bf + anchor, 1)

# 3. the Sources build phase
import re
m = re.search(r"(/\* Begin PBXSourcesBuildPhase section \*/.*?files = \(\n)(.*?)(\t\t\t\);)", t, re.S)
assert m, "sources phase not found"
t = t[:m.end(2)] + "\t\t\t\t%s /* probe.metal in Sources */,\n" % METAL_BUILD + t[m.end(2):]

# 4. drop the hand-added metallib resource (Xcode generates it)
t = t.replace(
    "\t\tA10000000000000000000021 /* default.metallib in Resources */ = {isa = PBXBuildFile; fileRef = "
    "A10000000000000000000020 /* default.metallib */; };\n", "")
t = t.replace("\t\t\t\tA10000000000000000000021 /* default.metallib in Resources */,\n", "")

pbx.write_text(t)
print("pbxproj patched: probe.metal in Sources")

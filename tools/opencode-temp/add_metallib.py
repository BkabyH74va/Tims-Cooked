#!/usr/bin/env python3
"""Add default.metallib to the AGXProbe app bundle (Resources phase)."""
import shutil
import sys
from pathlib import Path

proj = Path.home() / "agx-probe-project"
pbx = proj / "AGXProbe.xcodeproj" / "project.pbxproj"

shutil.copy(pbx, pbx.with_suffix(".pbxproj.bak2"))
t = pbx.read_text()

FILE_REF = "A10000000000000000000020"
BUILD_FILE = "A10000000000000000000021"

if FILE_REF in t:
    print("already patched")
    sys.exit(0)

# 1. file reference
anchor = "/* End PBXFileReference section */"
ref = (
    "\t\t%s /* default.metallib */ = {isa = PBXFileReference; lastKnownFileType = "
    "archive.metal-library; path = metal/default.metallib; sourceTree = SOURCE_ROOT; };\n"
    % FILE_REF
)
assert anchor in t
t = t.replace(anchor, ref + anchor, 1)

# 2. build file
anchor = "/* End PBXBuildFile section */"
bf = (
    "\t\t%s /* default.metallib in Resources */ = {isa = PBXBuildFile; fileRef = "
    "%s /* default.metallib */; };\n" % (BUILD_FILE, FILE_REF)
)
assert anchor in t
t = t.replace(anchor, bf + anchor, 1)

# 3. resources phase
old = """			files = (
			);"""
new = """			files = (
				%s /* default.metallib in Resources */,
			);""" % BUILD_FILE
assert old in t
t = t.replace(old, new, 1)

pbx.write_text(t)
print("patched pbxproj")

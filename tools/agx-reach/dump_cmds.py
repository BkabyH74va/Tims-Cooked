#!/usr/bin/env python3
"""Dump all load commands from kernelcache to understand its structure."""
import struct
from pathlib import Path

KC = Path("G:/REPO/firmware/24A446/kernelcache.release.macho")

data = KC.read_bytes()
magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack_from(
    "<IiiIIIII", data, 0
)

print(f"Magic: {magic:#x}")
print(f"Filetype: {filetype}")
print(f"Ncmds: {ncmds}")
print(f"Sizeofcmds: {sizeofcmds}")
print()

# Known command types
CMD_NAMES = {
    0x1: "LC_SEGMENT",
    0x2: "LC_SYMTAB",
    0x3: "LC_THREAD",
    0x4: "LC_UNIXTHREAD",
    0x5: "LC_LOADFVMLIB",
    0x6: "LC_IDFVMLIB",
    0x7: "LC_IDENT",
    0x8: "LC_FVMFILE",
    0x9: "LC_PREPAGE",
    0xA: "LC_DYSYMTAB",
    0xB: "LC_LOAD_DYLIB",
    0xC: "LC_ID_DYLIB",
    0xD: "LC_LOAD_DYLINKER",
    0xE: "LC_ID_DYLINKER",
    0xF: "LC_PREBOUND_DYLIB",
    0x10: "LC_ROUTINES",
    0x11: "LC_SUB_FRAMEWORK",
    0x12: "LC_SUB_UMBRELLA",
    0x13: "LC_SUB_CLIENT",
    0x14: "LC_SUB_LIBRARY",
    0x15: "LC_TWOLEVEL_HINTS",
    0x16: "LC_PREBOUND_DYLIB_ONLY",
    0x17: "LC_ROUTINES_64",
    0x18: "LC_SUB_UMBRELLA_64",
    0x19: "LC_SEGMENT_64",
    0x1A: "LC_ROUTINES_64",  # Actually this might be different
    0x1B: "LC_UNIXTHREAD_64",
    0x1C: "LC_LOAD_UPWARD_DYLIB",
    0x1D: "LC_CODE_SIGNATURE",
    0x1E: "LC_SEGMENT_SPLIT_INFO",
    0x1F: "LC_REPRO_DYLIB",
    0x20: "LC_DYLD_CODE_SIGN_DRS",
    0x21: "LC_ENCRYPTION_INFO_64",
    0x22: "LC_DYLD_INFO_ONLY",
    0x23: "LC_LOAD_UPWARD_DYLIB",
    0x24: "LC_FILESET_ENTRY",
    0x25: "LC_DATA_IN_CODE",
    0x26: "LC_SOURCE_VERSION",
    0x27: "LC_DYLIB_CODE_SIGN_DRS",
    0x28: "LC_ENCRYPTION_INFO",
    0x29: "LC_LINKER_OPTION",
    0x2A: "LC_LINKER_OPTIMIZATION_HINT",
    0x2B: "LC_FUNCTION_STARTS",
    0x2C: "LC_DYLD_ENVIRONMENT",
    0x2D: "LC_MAIN",
    0x2E: "LC_DATA_IN_CODE",
    0x2F: "LC_FILESET_ENTRY",  # Might be different
}

off = 32
cmd_counts = {}
for i in range(ncmds):
    cmd, cmdsize = struct.unpack_from("<II", data, off)
    name = CMD_NAMES.get(cmd, f"UNKNOWN_0x{cmd:X}")
    cmd_counts[cmd] = cmd_counts.get(cmd, 0) + 1
    if i < 30 or cmd == 0x24:
        print(f"  Cmd {i}: {name} (0x{cmd:X}) cmdsize={cmdsize}")
    off += cmdsize

print(f"\n=== Command type counts ===")
for cmd, count in sorted(cmd_counts.items()):
    name = CMD_NAMES.get(cmd, f"UNKNOWN_0x{cmd:X}")
    print(f"  0x{cmd:X} ({name}): {count}")

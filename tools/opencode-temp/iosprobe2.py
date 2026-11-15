#!/usr/bin/env python3
"""Sweep the IOSurfaceRoot client types from the current (out-of-app-sandbox)
context and, for every type that opens, exercise the gated IOSurfaceRootUserClient
methods.  The client type decides the capability bits (client+0x122), so a type
that opens here may unlock methods our sandboxed app cannot reach.
"""
import ctypes
import os
import sys

lib = ctypes.CDLL('/System/Library/Frameworks/IOKit.framework/IOKit')
u32 = ctypes.c_uint32
u64 = ctypes.c_uint64

lib.IOServiceMatching.restype = ctypes.c_void_p
lib.IOServiceMatching.argtypes = [ctypes.c_char_p]
lib.IOServiceGetMatchingService.restype = ctypes.c_void_p
lib.IOServiceGetMatchingService.argtypes = [u32, ctypes.c_void_p]
lib.IOServiceOpen.restype = u32
lib.IOServiceOpen.argtypes = [u32, u32, u32, ctypes.POINTER(u32)]
lib.IOServiceClose.restype = u32
lib.IOServiceClose.argtypes = [u32]
lib.IOConnectCallMethod.restype = u32
lib.IOConnectCallMethod.argtypes = [
    u32, u32,
    ctypes.POINTER(u64), u32,
    ctypes.c_void_p, u32,
    ctypes.POINTER(u64), ctypes.POINTER(u32),
    ctypes.c_void_p, ctypes.POINTER(u64)]


def kr(n):
    return {0: "OK", 0xe00002bd: "NoMemory", 0xe00002bf: "IPCError",
            0xe00002c1: "BadMatching", 0xe00002c2: "BadArgument",
            0xe00002c7: "Unsupported", 0xe00002c9: "Duplicate",
            0xe00002d8: "NotAttached"}.get(n, "0x%08x" % n)


def call(conn, sel, scalars, sin, sout):
    n = len(scalars)
    sa = (u64 * max(n, 1))()
    for i, v in enumerate(scalars):
        sa[i] = v
    oc = (u64 * 2)()
    ocnt = u32(0)
    osz = u64(len(sout))
    bi = (ctypes.c_ubyte * max(len(sin), 1))()
    for i, b in enumerate(sin):
        bi[i] = b
    bo = (ctypes.c_ubyte * max(len(sout), 1))()
    r = lib.IOConnectCallMethod(
        conn, sel,
        ctypes.cast(sa, ctypes.POINTER(u64)) if n else None, n,
        ctypes.cast(bi, ctypes.c_void_p) if sin else None, len(sin),
        ctypes.cast(oc, ctypes.POINTER(u64)), ctypes.byref(ocnt),
        ctypes.cast(bo, ctypes.c_void_p) if sout else None, ctypes.byref(osz))
    return r, bytes(bytearray(bo[:min(osz.value, 24)]))


m = lib.IOServiceMatching(b"IOSurfaceRoot")
svc = lib.IOServiceGetMatchingService(0, m)
print("uid=%d  IOSurfaceRoot service=0x%x" % (os.getuid(), svc or 0))
if not svc:
    sys.exit(0)

# the interesting names, in case a lookup by name is what the service wants
for nm in (b"IOSurfaceRoot", b"IOSurfaceRootUserClient", b"IOSurfaceUserClient"):
    mm = lib.IOServiceMatching(nm)
    ss = lib.IOServiceGetMatchingService(0, mm)
    print("  match %-26s -> 0x%x" % (nm.decode(), ss or 0))
    if ss:
        c = u32(0)
        r = lib.IOServiceOpen(ss, 0, 0, ctypes.byref(c))
        print("     open type=0 -> %s conn=0x%x" % (kr(r), c.value))
        if r == 0:
            for sel, scalars, sinlen, soutlen in [(0x1e, [0], 0x80, 0xc68),
                                                 (0x1a, [], 0x80, 0x1000),
                                                 (0x22, [0], 0, 0xc68),
                                                 (0x06, [], 0x20, 0xc68),
                                                 (0x00, [0], 0x400, 0xc68)]:
                rr, head = call(c.value, sel, scalars, bytes([0x41] * sinlen), bytes(soutlen))
                print("     sel 0x%02x -> %s out=%s" % (sel, kr(rr), head[:16].hex()))
            lib.IOServiceClose(c)

# type sweep on the plain IOSurfaceRoot
for t in range(0, 8):
    c = u32(0)
    r = lib.IOServiceOpen(svc, 0, t, ctypes.byref(c))
    print("IOServiceOpen(IOSurfaceRoot, type=%d) -> %s conn=0x%x" % (t, kr(r), c.value))
    if r == 0:
        lib.IOServiceClose(c)

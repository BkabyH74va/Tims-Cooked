#!/usr/bin/env python3
"""Probe IOSurfaceRoot from the SSH (out-of-app-sandbox) context.

Compares the return codes of the gated IOSurfaceRootUserClient methods with
what the sandboxed app gets.  If the sandbox was the only thing gating them,
these calls will behave differently here.
"""
import ctypes
import ctypes.util
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
lib.IOServiceClose.restype = kern = u32
lib.IOServiceClose.argtypes = [u32]
lib.IOConnectCallMethod.restype = u32
lib.IOConnectCallMethod.argtypes = [
    u32, u32,
    ctypes.POINTER(u64), u32,
    ctypes.c_void_p, u32,
    ctypes.POINTER(u64), ctypes.POINTER(u32),
    ctypes.c_void_p, ctypes.POINTER(u64)]


def kr(name):
    return {
        0: "OK",
        0xe00002bd: "NoMemory",
        0xe00002bf: "IPCError",
        0xe00002c1: "BadMatching",
        0xe00002c2: "BadArgument",
        0xe00002c9: "Duplicate",
        0xe00002d8: "NotAttached",
    }.get(name, "0x%08x" % name)


def call(conn, sel, scalars, sin, sout):
    n = len(scalars)
    sa = (u64 * max(n, 1))()
    for i, v in enumerate(scalars):
        sa[i] = v
    oc = (u64 * 2)()
    ocnt = u32(0)
    osz = u64(len(sout))
    buf_in = (ctypes.c_ubyte * max(len(sin), 1))()
    for i, b in enumerate(sin):
        buf_in[i] = b
    buf_out = (ctypes.c_ubyte * max(len(sout), 1))()
    r = lib.IOConnectCallMethod(conn, sel,
                               ctypes.cast(sa, ctypes.POINTER(u64)) if n else None, n,
                               ctypes.cast(buf_in, ctypes.c_void_p) if sin else None, len(sin),
                               ctypes.cast(oc, ctypes.POINTER(u64)) if True else None, ctypes.byref(ocnt),
                               ctypes.cast(buf_out, ctypes.c_void_p) if sout else None, ctypes.byref(osz))
    return r, bytes(bytearray(buf_out[:min(osz.value, 32)]))


def main():
    print("uid/gid:", __import__("os").getuid(), __import__("os").getgid())
    m = lib.IOServiceMatching(b"IOSurfaceRoot")
    svc = lib.IOServiceGetMatchingService(0, m)
    print("IOSurfaceRoot service = 0x%x" % (svc or 0))
    if not svc:
        return
    conn = u32(0)
    r = lib.IOServiceOpen(svc, 0, 0, ctypes.byref(conn))
    print("IOServiceOpen type=0 -> 0x%08x conn=0x%x" % (r, conn.value))
    if r != 0:
        return

    # the three methods that reach real code from the sandboxed app
    for sel, scalars, sinlen, soutlen in [
        (0x1e, [0], 0x80, 0xc68),
        (0x1a, [], 0x80, 0x1000),
        (0x22, [0], 0, 0xc68),
        (0x06, [], 0x20, 0xc68),
    ]:
        sin = bytes([0x41] * sinlen)
        sout = bytes(soutlen)
        rr, head = call(conn.value, sel, scalars, sin, sout)
        print("sel 0x%02x scalars=%s sin=%#x -> %s  outhead=%s" %
              (sel, scalars, sinlen, kr(rr), head[:16].hex()))
    lib.IOServiceClose(conn)


main()

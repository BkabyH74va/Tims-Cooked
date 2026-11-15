#!/usr/bin/env python3
"""Probe every plausible debugger service and see which one actually speaks
gdb-remote on the other end.

Tries:
  * lockdown/usbmux services: com.apple.debugserver, ...DVTSecureSocketProxy, ...
  * RSD services (no RemoteXPC handshake): com.apple.internal.dt.remote.debugproxy,
    com.apple.coredevice.debugserverproxy

For each service that connects we send a plain gdb-remote ``qHostInfo`` and
report whatever bytes come back (or that nothing does).
"""
import asyncio
import sys
import time

from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.remote import userspace_tunnel

UDID = "REDACTED_DEVICE_ID"

LOCKDOWN_SERVICES = [
    "com.apple.debugserver",
    "com.apple.debugserver.DVTSecureSocketProxy",
    "com.apple.debugserver.shim.remote",
]

RSD_SERVICES = [
    "com.apple.internal.dt.remote.debugproxy",
    "com.apple.coredevice.debugserverproxy",
]

QHOSTINFO = b"$qHostInfo#2c"


async def try_stream(label, reader, writer):
    writer.write(QHOSTINFO)
    await writer.drain()
    t0 = time.time()
    try:
        data = await asyncio.wait_for(reader.read(4096), 10)
    except asyncio.TimeoutError:
        print(f"  {label}: connected, but NO reply in 10s")
        return
    if not data:
        print(f"  {label}: connected, server closed immediately (EOF)")
        return
    print(f"  {label}: reply after {time.time()-t0:.2f}s: {data[:200]!r}")


async def probe_lockdown():
    print("== lockdown (usbmux) services ==", flush=True)
    lockdown = await create_using_usbmux(serial=UDID, autopair=False)
    for name in LOCKDOWN_SERVICES:
        print(f"- {name}", flush=True)
        try:
            conn = await lockdown.start_lockdown_service(name)
        except Exception as e:
            print(f"  cannot start: {type(e).__name__}: {e}")
            continue
        try:
            await try_stream(name, conn.reader, conn.writer)
        finally:
            await conn.close()


async def probe_rsd():
    print("== RSD services (raw TCP, no RemoteXPC handshake) ==", flush=True)
    rsd = await userspace_tunnel.establish_userspace_rsd(serial=UDID)
    for name in RSD_SERVICES:
        print(f"- {name}", flush=True)
        try:
            conn = await rsd.start_lockdown_service_without_checkin(name)
        except Exception as e:
            print(f"  cannot start: {type(e).__name__}: {e}")
            continue
        try:
            await try_stream(name, conn.reader, conn.writer)
        finally:
            await conn.close()


async def main():
    await probe_lockdown()
    print(flush=True)
    await probe_rsd()


if __name__ == "__main__":
    asyncio.run(main())

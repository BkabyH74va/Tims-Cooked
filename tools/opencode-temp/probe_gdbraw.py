#!/usr/bin/env python3
"""Talk raw gdb-remote to the device's debugproxy service and print the replies."""
import asyncio
import sys
import time

from pymobiledevice3.remote import userspace_tunnel

UDID = "REDACTED_DEVICE_ID"
SERVICE = "com.apple.internal.dt.remote.debugproxy"


def cksum(body: str) -> str:
    return "%02x" % (sum(body.encode()) & 0xFF)


def pkt(body: str) -> bytes:
    return ("$" + body + "#" + cksum(body)).encode()


async def read_reply(reader, timeout=6.0):
    try:
        data = await asyncio.wait_for(reader.read(4096), timeout)
    except asyncio.TimeoutError:
        return None
    return data


async def main():
    rsd = await userspace_tunnel.establish_userspace_rsd(serial=UDID)
    conn = await rsd.start_lockdown_service_without_checkin(SERVICE)
    reader, writer = conn.reader, conn.writer

    probes = [
        pkt("qHostInfo"),
        pkt("qSupported:multiprocess+;swarm+;xmlRegisters=aarch64"),
        pkt("qProcessInfo"),
        pkt("vCont?"),
        pkt("qC"),
        pkt("qAttached"),
        pkt("qTStatus"),
        pkt("?"),
    ]

    for p in probes:
        writer.write(p)
        await writer.drain()
        t0 = time.time()
        reply = await read_reply(reader)
        print(f"--> {p!r}\n<-- {reply!r}  ({time.time()-t0:.2f}s)", flush=True)
        if reply is None:
            break

    await conn.close()


if __name__ == "__main__":
    asyncio.run(main())

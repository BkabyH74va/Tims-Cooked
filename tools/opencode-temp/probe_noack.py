#!/usr/bin/env python3
"""Compare the device's gdb-remote replies with and without $QStartNoAckMode."""
import asyncio
import sys

from pymobiledevice3.remote import userspace_tunnel

UDID = "REDACTED_DEVICE_ID"
SERVICE = "com.apple.internal.dt.remote.debugproxy"


def pkt(body: str) -> bytes:
    return ("$" + body + "#%02x" % (sum(body.encode()) & 0xFF)).encode()


async def drain(reader, label, timeout=2.0):
    out = b""
    deadline = asyncio.get_event_loop().time() + timeout
    while True:
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            break
        try:
            data = await asyncio.wait_for(reader.read(4096), remaining)
        except asyncio.TimeoutError:
            break
        if not data:
            print(f"  [{label}] EOF")
            break
        out += data
    print(f"  [{label}] {out!r}")
    return out


async def run(no_ack: bool):
    rsd = await userspace_tunnel.establish_userspace_rsd(serial=UDID)
    conn = await rsd.start_lockdown_service_without_checkin(SERVICE)
    reader, writer = conn.reader, conn.writer
    print(f"=== no_ack_mode={not no_ack} ===", flush=True)

    if no_ack:
        writer.write(pkt("QStartNoAckMode"))
        await writer.drain()
        await drain(reader, "after QStartNoAckMode")

    for body in ("qHostInfo", "qC", "qProcessInfo", "vCont?", "qAttached"):
        writer.write(pkt(body))
        await writer.drain()
        await drain(reader, f"after {body}", timeout=1.5)

    await conn.close()


async def main():
    await run(no_ack=False)
    print(flush=True)
    await run(no_ack=True)


if __name__ == "__main__":
    asyncio.run(main())

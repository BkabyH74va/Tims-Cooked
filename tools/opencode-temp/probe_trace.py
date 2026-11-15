#!/usr/bin/env python3
"""Timestamped dump of the device's gdb-remote stream.

Sends one packet every 3 seconds and records exactly what comes back, so the
ack/response ordering (and the stray 'N' / zero-checksum behaviour) is visible.
"""
import asyncio
import time

from pymobiledevice3.remote import userspace_tunnel

UDID = "REDACTED_DEVICE_ID"
SERVICE = "com.apple.internal.dt.remote.debugproxy"


def pkt(body: str) -> bytes:
    return ("$" + body + "#%02x" % (sum(body.encode()) & 0xFF)).encode()


async def main():
    rsd = await userspace_tunnel.establish_userspace_rsd(serial=UDID)
    conn = await rsd.start_lockdown_service_without_checkin(SERVICE)
    reader, writer = conn.reader, conn.writer
    t0 = time.time()

    async def reader_task():
        while True:
            data = await reader.read(4096)
            if not data:
                print(f"[{time.time()-t0:6.2f}] <EOF", flush=True)
                return
            print(f"[{time.time()-t0:6.2f}] <-- {data!r}", flush=True)

    task = asyncio.create_task(reader_task())

    for body in ("QStartNoAckMode", "qHostInfo", "qC", "qProcessInfo", "vCont?", "qAttached", "qfThreadInfo"):
        print(f"[{time.time()-t0:6.2f}] --> {pkt(body)!r}", flush=True)
        writer.write(pkt(body))
        await writer.drain()
        await asyncio.sleep(3)

    task.cancel()
    await conn.close()


if __name__ == "__main__":
    asyncio.run(main())

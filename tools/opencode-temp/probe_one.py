#!/usr/bin/env python3
"""Send exactly ONE gdb-remote query on a fresh connection and print the reply.

Avoids any ambiguity about which reply belongs to which query.
Usage: probe_one.py <query> [service]
"""
import asyncio
import sys
import time

from pymobiledevice3.remote import userspace_tunnel
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl

UDID = "REDACTED_DEVICE_ID"
BUNDLE = "com.nianticlabs.pokemongo.4L9HF29JJU"


def pkt(body: str) -> bytes:
    return ("$" + body + "#%02x" % (sum(body.encode()) & 0xFF)).encode()


async def main():
    query = sys.argv[1]
    service = sys.argv[2] if len(sys.argv) > 2 else "com.apple.internal.dt.remote.debugproxy"

    rsd = await userspace_tunnel.establish_userspace_rsd(serial=UDID)
    async with DvtProvider(rsd) as dvt, ProcessControl(dvt) as pc:
        pid = await pc.process_identifier_for_bundle_identifier(BUNDLE)
    if pid <= 0:
        pid = await pc.launch(bundle_id=BUNDLE, kill_existing=False, start_suspended=True)
    query = query.replace("{pid}", str(pid))

    conn = await rsd.start_lockdown_service_without_checkin(service)
    reader, writer = conn.reader, conn.writer

    # let the session settle, then send exactly one query
    await asyncio.sleep(0.5)
    writer.write(pkt(query))
    await writer.drain()

    out = b""
    end = time.time() + 8
    while time.time() < end:
        try:
            data = await asyncio.wait_for(reader.read(4096), 2.0)
        except asyncio.TimeoutError:
            break
        if not data:
            out += b"<EOF>"
            break
        out += data

    print(f"pid={pid} query={query!r}\n  -> {out!r}", flush=True)
    await conn.close()


if __name__ == "__main__":
    asyncio.run(main())

#!/usr/bin/env python3
"""Attach probe in the device's *no-ack* mode (the mode the debugserver seems
to prefer), but without enabling compression so replies stay plain."""
import asyncio
import sys
import time

from pymobiledevice3.remote import userspace_tunnel
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl

UDID = "REDACTED_DEVICE_ID"
BUNDLE = "com.nianticlabs.pokemongo.4L9HF29JJU"
SERVICE = "com.apple.internal.dt.remote.debugproxy"


def pkt(body: str) -> bytes:
    return ("$" + body + "#%02x" % (sum(body.encode()) & 0xFF)).encode()


async def drain(reader, quiet=1.5, limit=10.0):
    out = b""
    end = time.time() + limit
    while time.time() < end:
        try:
            data = await asyncio.wait_for(reader.read(4096), quiet)
        except asyncio.TimeoutError:
            break
        if not data:
            out += b"<EOF>"
            break
        out += data
    return out


async def main():
    rsd = await userspace_tunnel.establish_userspace_rsd(serial=UDID)
    async with DvtProvider(rsd) as dvt, ProcessControl(dvt) as pc:
        pid = await pc.process_identifier_for_bundle_identifier(BUNDLE)
        if pid <= 0:
            pid = await pc.launch(bundle_id=BUNDLE, kill_existing=False, start_suspended=True)
    print(f"pid {pid}", flush=True)

    conn = await rsd.start_lockdown_service_without_checkin(SERVICE)
    reader, writer = conn.reader, conn.writer

    async def ask(body, label=None):
        label = label or body
        writer.write(pkt(body))
        await writer.drain()
        reply = await drain(reader)
        print(f"  {label}\n     -> {reply!r}", flush=True)
        return reply

    await ask("QStartNoAckMode", "QStartNoAckMode")
    await ask("qHostInfo")
    await ask(f"qAttach:{pid}", f"qAttach:{pid}")
    await ask("?", "stop reason")
    await ask("qfThreadInfo")
    await ask("qProcessInfo")
    await ask("qC")
    await conn.close()


if __name__ == "__main__":
    asyncio.run(main())

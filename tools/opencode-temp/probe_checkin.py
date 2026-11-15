#!/usr/bin/env python3
"""Same attach probe, but the debugproxy service is opened WITH the RSD
check-in handshake (which carries the host identity/entitlement)."""
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


async def drain(reader, quiet=1.2, limit=8.0):
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

    print("opening service WITH RSD check-in...", flush=True)
    try:
        conn = await rsd.start_lockdown_service(SERVICE)
    except Exception as e:
        print(f"  check-in failed: {type(e).__name__}: {e}", flush=True)
        conn = await rsd.start_lockdown_service_without_checkin(SERVICE)
        print("  falling back to no-checkin", flush=True)
    reader, writer = conn.reader, conn.writer

    async def ask(body, label=None):
        label = label or body
        writer.write(pkt(body))
        await writer.drain()
        reply = await drain(reader)
        print(f"  {label}\n     -> {reply!r}", flush=True)
        return reply

    await ask("qHostInfo")
    await ask(f"qAttach:{pid}", f"qAttach:{pid}")
    await ask("?", "stop reason")
    await ask("qfThreadInfo")
    await ask("qProcessInfo")
    await ask("qC")
    await conn.close()


if __name__ == "__main__":
    asyncio.run(main())

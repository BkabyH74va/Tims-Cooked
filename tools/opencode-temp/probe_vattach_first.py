#!/usr/bin/env python3
"""Send vAttach as the FIRST packet on a fresh debugproxy connection."""
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


async def drain(reader, quiet=2.0, limit=10.0):
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


async def try_first_packet(rsd, pid, first_body, subsequent_queries):
    conn = await rsd.start_lockdown_service_without_checkin(SERVICE)
    reader, writer = conn.reader, conn.writer

    async def ask(body):
        writer.write(pkt(body))
        await writer.drain()
        return await drain(reader)

    # First packet is the attach/launch attempt
    reply = await ask(first_body)
    print(f"  FIRST {first_body}\n     -> {reply!r}", flush=True)

    # Then do the normal handshake
    for q in subsequent_queries:
        r = await ask(q)
        print(f"  then {q}\n     -> {r!r}", flush=True)

    # Check state
    r = await ask("?")
    print(f"  state ?\n     -> {r!r}", flush=True)
    r = await ask("qfThreadInfo")
    print(f"  threads\n     -> {r!r}", flush=True)
    r = await ask("qProcessInfo")
    print(f"  procinfo\n     -> {r!r}", flush=True)

    await conn.close()


async def main():
    rsd = await userspace_tunnel.establish_userspace_rsd(serial=UDID)
    async with DvtProvider(rsd) as dvt, ProcessControl(dvt) as pc:
        pid = await pc.process_identifier_for_bundle_identifier(BUNDLE)
        if pid <= 0:
            pid = await pc.launch(bundle_id=BUNDLE, kill_existing=False, start_suspended=True)
    print(f"pid {pid} (hex {pid:x})", flush=True)

    handshake = [
        "qHostInfo",
        "qSupported:xmlRegisters=i386,arm,mips,arc;multiprocess+;fork-events+;vfork-events+;"
        "swbreak+;hwbreak+;qXfer:libraries:read+;qXfer:libraries-svr4:read+",
    ]

    variants = [
        f"vAttach;{pid:x}",
        f"vAttach;{pid}",
        f"qAttach;{pid}",
    ]

    for v in variants:
        try:
            await try_first_packet(rsd, pid, v, handshake)
        except Exception as e:  # noqa: BLE001
            print(f"  {v}: ERROR {type(e).__name__}: {e}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())

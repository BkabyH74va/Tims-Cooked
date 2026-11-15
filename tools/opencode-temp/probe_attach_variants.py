#!/usr/bin/env python3
"""Try every attach-packet spelling the device might implement, one fresh
connection each, after a full handshake."""
import asyncio
import sys
import time

from pymobiledevice3.remote import userspace_tunnel
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl

UDID = "REDACTED_DEVICE_ID"
BUNDLE = "com.nianticlabs.pokemongo.4L9HF29JJU"
SERVICE = "com.apple.internal.dt.remote.debugproxy"

HANDSHAKE = [
    "qHostInfo",
    "qSupported:xmlRegisters=i386,arm,mips,arc;multiprocess+;fork-events+;vfork-events+;"
    "swbreak+;hwbreak+;qXfer:libraries:read+;qXfer:libraries-svr4:read+",
    "QThreadSuffixSupported",
    "QListThreadsInStopReply",
    "vCont?",
    "qVAttachOrWaitSupported",
    "QEnableErrorStrings",
]


def pkt(body: str) -> bytes:
    return ("$" + body + "#%02x" % (sum(body.encode()) & 0xFF)).encode()


async def drain(reader, quiet=2.5, limit=20.0):
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


async def try_packet(rsd, pid, packet_body):
    conn = await rsd.start_lockdown_service_without_checkin(SERVICE)
    reader, writer = conn.reader, conn.writer

    async def ask(body):
        writer.write(pkt(body))
        await writer.drain()
        return await drain(reader, quiet=0.8, limit=4.0)

    for q in HANDSHAKE:
        await ask(q)
    reply = await ask(packet_body)
    state = await ask("?")
    threads = await ask("qfThreadInfo")
    print(f"  {packet_body}\n      attach-> {reply!r}\n      '?'  -> {state!r}\n      thr  -> {threads!r}", flush=True)
    await conn.close()


async def main():
    rsd = await userspace_tunnel.establish_userspace_rsd(serial=UDID)
    async with DvtProvider(rsd) as dvt, ProcessControl(dvt) as pc:
        pid = await pc.process_identifier_for_bundle_identifier(BUNDLE)
        if pid <= 0:
            pid = await pc.launch(bundle_id=BUNDLE, kill_existing=False, start_suspended=True)
    print(f"pid {pid} (hex {pid:x})", flush=True)

    variants = [
        f"vAttach;{pid:x}",            # LLDB / Apple form (hex)
        f"vAttach;{pid}",              # decimal
        f"vAttachOrWait;{pid:x}",
        f"vAttachWait;{pid:x}",
        f"vAttachName;AGXProbe",
        f"qAttach;{pid}",
        f"vAttach;{pid:x};1",
    ]
    for v in variants:
        try:
            await try_packet(rsd, pid, v)
        except Exception as e:  # noqa: BLE001
            print(f"  {v}: ERROR {type(e).__name__}: {e}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())

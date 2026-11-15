#!/usr/bin/env python3
"""Replay LLDB's exact handshake against the device's debugserver and only
then send the vAttach packet.  If the device ignored vAttach before because
the handshake was incomplete, it should answer now."""
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
    "qHostInfo",
    "vCont?",
    "qVAttachOrWaitSupported",
    "QEnableErrorStrings",
    "qProcessInfo",
    "qC",
    "qfThreadInfo",
]


def pkt(body: str) -> bytes:
    return ("$" + body + "#%02x" % (sum(body.encode()) & 0xFF)).encode()


async def read_reply(reader, timeout=8.0):
    """Read until a full packet arrives."""
    buf = b""
    end = time.time() + timeout
    while time.time() < end:
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout)
        except asyncio.TimeoutError:
            return buf + b"<TIMEOUT>"
        if not data:
            return buf + b"<EOF>"
        buf += data
        if b"#" in buf:
            # crude: a complete packet ends with #xx
            idx = buf.rfind(b"#")
            if len(buf) >= idx + 3:
                return buf
    return buf + b"<TIMEOUT>"


async def main():
    rsd = await userspace_tunnel.establish_userspace_rsd(serial=UDID)
    async with DvtProvider(rsd) as dvt, ProcessControl(dvt) as pc:
        pid = await pc.process_identifier_for_bundle_identifier(BUNDLE)
        if pid <= 0:
            pid = await pc.launch(bundle_id=BUNDLE, kill_existing=False, start_suspended=True)
    print(f"pid {pid} (hex {pid:x})", flush=True)

    conn = await rsd.start_lockdown_service_without_checkin(SERVICE)
    reader, writer = conn.reader, conn.writer

    async def ask(body, label=None):
        label = label or body
        writer.write(pkt(body))
        await writer.drain()
        reply = await read_reply(reader)
        print(f"  {label}\n     -> {reply!r}", flush=True)
        return reply

    for q in HANDSHAKE:
        await ask(q)

    await ask(f"vAttach;{pid:x}", f"vAttach;{pid:x}  (after full handshake)")
    await ask("?", "stop reason")
    await ask("qfThreadInfo")
    await ask("qProcessInfo")
    await conn.close()


if __name__ == "__main__":
    asyncio.run(main())

#!/usr/bin/env python3
"""After a full handshake, ask the device's debugserver to LAUNCH the app
itself (LLDB's 'A' packet format) and check whether an inferior appears."""
import asyncio
import sys
import time

from pymobiledevice3.remote import userspace_tunnel
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl
from pymobiledevice3.services.installation_proxy import InstallationProxyService

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


def launch_packet(path: str) -> str:
    raw = path.encode()
    return "A,%x,0,%s" % (len(raw) * 2, raw.hex())


async def drain(reader, quiet=2.0, limit=15.0):
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
    async with InstallationProxyService(lockdown=rsd) as ip:
        apps = await ip.get_apps(bundle_identifiers=[BUNDLE])
    exe = apps[BUNDLE]["Path"] + "/AGXProbe"

    async with DvtProvider(rsd) as dvt, ProcessControl(dvt) as pc:
        pid = await pc.process_identifier_for_bundle_identifier(BUNDLE)
        if pid > 0:
            print(f"killing running instance {pid}", flush=True)
            await pc.kill(pid)
            await asyncio.sleep(2)

    conn = await rsd.start_lockdown_service_without_checkin(SERVICE)
    reader, writer = conn.reader, conn.writer

    async def ask(body, label=None):
        label = label or body
        writer.write(pkt(body))
        await writer.drain()
        reply = await drain(reader)
        print(f"  {label}\n     -> {reply!r}", flush=True)
        return reply

    for q in HANDSHAKE:
        await ask(q)

    await ask(launch_packet(exe), "A (launch app via debugserver)")
    await ask("qLaunchSuccess", "qLaunchSuccess")
    await ask("?", "stop reason")
    await ask("qfThreadInfo")
    await ask("qProcessInfo")
    await ask("qC")
    await conn.close()


if __name__ == "__main__":
    asyncio.run(main())

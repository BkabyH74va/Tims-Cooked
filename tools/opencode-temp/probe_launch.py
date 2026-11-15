#!/usr/bin/env python3
"""Launch the app through the device debugserver with the gdb-remote 'A' packet,
then check that we really have an inferior attached."""
import asyncio
import sys
import time

from pymobiledevice3.remote import userspace_tunnel
from pymobiledevice3.services.installation_proxy import InstallationProxyService

UDID = "REDACTED_DEVICE_ID"
BUNDLE = "com.nianticlabs.pokemongo.4L9HF29JJU"
SERVICE = "com.apple.internal.dt.remote.debugproxy"


def pkt(body: str) -> bytes:
    return ("$" + body + "#%02x" % (sum(body.encode()) & 0xFF)).encode()


def launch_packet(path: str) -> str:
    raw = path.encode()
    return "A%x,0,%s" % (len(raw) * 2, raw.hex())


async def drain(reader, quiet=1.0, limit=8.0):
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
    app_path = apps[BUNDLE]["Path"]
    print(f"app path: {app_path}", flush=True)

    candidate = sys.argv[1] if len(sys.argv) > 1 else app_path
    if candidate == "exe":
        candidate = app_path + "/AGXProbe"
    print(f"launching: {candidate}", flush=True)

    conn = await rsd.start_lockdown_service_without_checkin(SERVICE)
    reader, writer = conn.reader, conn.writer

    async def ask(body, label=None):
        label = label or body
        writer.write(pkt(body))
        await writer.drain()
        reply = await drain(reader)
        print(f"  {label}\n     -> {reply!r}", flush=True)
        return reply

    await ask("qHostInfo")
    await ask(launch_packet(candidate), "A (launch)")
    await ask("qLaunchSuccess", "qLaunchSuccess")
    await ask("?", "stop reason")
    await ask("qfThreadInfo")
    await ask("qProcessInfo")
    await ask("qC")

    await conn.close()


if __name__ == "__main__":
    asyncio.run(main())

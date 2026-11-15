#!/usr/bin/env python3
"""Find the packet that makes the device's debugserver attach to our app."""
import asyncio
import time

from pymobiledevice3.remote import userspace_tunnel
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl

UDID = "REDACTED_DEVICE_ID"
BUNDLE = "com.nianticlabs.pokemongo.4L9HF29JJU"
SERVICE = "com.apple.internal.dt.remote.debugproxy"


def pkt(body: str) -> bytes:
    return ("$" + body + "#%02x" % (sum(body.encode()) & 0xFF)).encode()


async def main():
    rsd = await userspace_tunnel.establish_userspace_rsd(serial=UDID)
    async with DvtProvider(rsd) as dvt, ProcessControl(dvt) as pc:
        pid = await pc.process_identifier_for_bundle_identifier(BUNDLE)
        print(f"target pid {pid}", flush=True)

    conn = await rsd.start_lockdown_service_without_checkin(SERVICE)
    reader, writer = conn.reader, conn.writer

    async def ask(body, label=None, timeout=6.0):
        label = label or body
        writer.write(pkt(body))
        await writer.drain()
        t0 = time.time()
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout)
        except asyncio.TimeoutError:
            print(f"  {label}: NO REPLY ({timeout}s)", flush=True)
            return None
        print(f"  {label}: {data!r}  ({time.time()-t0:.2f}s)", flush=True)
        return data

    print("== probing attach packets ==", flush=True)
    await ask("qHostInfo")
    await ask(f"qAttach:{pid}")
    await ask("?")
    await ask(f"vAttach;{pid}:0")
    await ask("?")
    await ask("qfThreadInfo")
    await ask(f"qAttach:{pid}")
    await ask("?")

    await conn.close()


if __name__ == "__main__":
    asyncio.run(main())

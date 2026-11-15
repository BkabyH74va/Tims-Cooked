#!/usr/bin/env python3
"""Look for the Instruments DTX 'debugserver' channel and probe its methods.

The classic Instruments debugger protocol lives on that channel: the host
listens on a port and asks the device to connect back with
'requestConnectionAtPort:', which yields a real per-process debugserver that
does accept vAttach.
"""
import asyncio

from pymobiledevice3.remote import userspace_tunnel
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider

UDID = "REDACTED_DEVICE_ID"

CANDIDATES = [
    "com.apple.instruments.server.services.debugserver",
    "com.apple.instruments.server.services.processcontrol",
    "com.apple.instruments.server.services.deviceinfo",
]


async def main():
    rsd = await userspace_tunnel.establish_userspace_rsd(serial=UDID)
    print("rsd service address:", rsd.service.address, flush=True)

    async with DvtProvider(rsd) as dvt:
        for ident in CANDIDATES:
            try:
                svc = await asyncio.wait_for(dvt.dtx.open_channel(ident), 15)
            except Exception as e:  # noqa: BLE001
                print(f"channel {ident}: FAILED {type(e).__name__}: {e}", flush=True)
                continue
            print(f"channel {ident}: OPEN ({type(svc).__name__})", flush=True)
            chan = getattr(svc, "_channel", None)
            print(f"   channel obj: {chan!r}", flush=True)
            for selector, args in [
                ("requestConnectionAtPort:", (1234,)),
                ("attachToProcessWithIdentifier:", (1234,)),
                ("launchSuspendedProcessWithDevicePath:bundleIdentifier:environment:arguments:options:",
                 ("", "com.nianticlabs.pokemongo.4L9HF29JJU", {}, [], {})),
            ]:
                try:
                    reply = await asyncio.wait_for(chan.invoke(selector, *args), 15)
                    print(f"   {selector} -> {reply!r}", flush=True)
                except Exception as e:  # noqa: BLE001
                    print(f"   {selector} -> ERROR {type(e).__name__}: {e}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())

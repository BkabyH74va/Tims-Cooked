#!/usr/bin/env python3
"""Leave the device in a clean state: report/kill leftover AGXProbe instances
and check whether any crash reports were produced by our probes."""
import asyncio

from pymobiledevice3.remote import userspace_tunnel
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl

UDID = "REDACTED_DEVICE_ID"
BUNDLE = "com.nianticlabs.pokemongo.4L9HF29JJU"


async def main():
    rsd = await userspace_tunnel.establish_userspace_rsd(serial=UDID)
    async with DvtProvider(rsd) as dvt, ProcessControl(dvt) as pc:
        pid = await pc.process_identifier_for_bundle_identifier(BUNDLE)
        print(f"AGXProbe pid: {pid}")
        if pid > 0:
            print(f"killing {pid}")
            await pc.kill(pid)
            await asyncio.sleep(2)
        pid = await pc.process_identifier_for_bundle_identifier(BUNDLE)
        print(f"AGXProbe pid after cleanup: {pid}")


if __name__ == "__main__":
    asyncio.run(main())

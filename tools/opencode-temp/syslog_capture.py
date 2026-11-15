#!/usr/bin/env python3
"""Capture device syslog entries matching debug keywords for ~25s."""
import asyncio
import sys

from pymobiledevice3.remote import userspace_tunnel
from pymobiledevice3.services.syslog import SyslogService

UDID = "REDACTED_DEVICE_ID"
KEYWORDS = ("debugserver", "debugproxy", "vattach", "attach", "instruments", "agxprobe", "coredevice")


async def main():
    rsd = await userspace_tunnel.establish_userspace_rsd(serial=UDID)
    async with SyslogService(lockdown=rsd) as svc:
        async for line in svc.watch():
            s = line if isinstance(line, str) else line.decode(errors="replace")
            if any(k in s.lower() for k in KEYWORDS):
                print(s[:400], flush=True)


asyncio.run(main())

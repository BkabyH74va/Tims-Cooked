#!/usr/bin/env python3
"""Probe the Instruments 'debugserver' DTX channel for the selector that hands
us a real per-process debugserver (which does accept vAttach).

Every attempt uses a fresh channel, because a wrong selector/argument makes the
device cancel the channel.
"""
import asyncio
import sys

from pymobiledevice3.remote import userspace_tunnel
from pymobiledevice3.remote.userspace_tunnel import userspace_stack_addr
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl

UDID = "REDACTED_DEVICE_ID"
BUNDLE = "com.nianticlabs.pokemongo.4L9HF29JJU"
CHANNEL = "com.apple.instruments.server.services.debugserver"


async def attempt(dvt, selector, args, label):
    try:
        svc = await asyncio.wait_for(dvt.dtx.open_channel(CHANNEL), 15)
    except Exception as e:  # noqa: BLE001
        print(f"[{label}] channel open failed: {type(e).__name__}: {e}", flush=True)
        return
    chan = svc._channel
    try:
        reply = await asyncio.wait_for(chan.invoke(selector, *args), 12)
        print(f"[{label}] {selector}{args!r} -> {reply!r}", flush=True)
    except Exception as e:  # noqa: BLE001
        print(f"[{label}] {selector}{args!r} -> {type(e).__name__}: {e}", flush=True)


async def main():
    rsd = await userspace_tunnel.establish_userspace_rsd(serial=UDID)
    host_addr = userspace_stack_addr()
    print(f"device tunnel addr: {rsd.service.address}", flush=True)
    print(f"host   tunnel addr: {host_addr}", flush=True)

    async with DvtProvider(rsd) as dvt, ProcessControl(dvt) as pc:
        pid = await pc.process_identifier_for_bundle_identifier(BUNDLE)
        if pid <= 0:
            pid = await pc.launch(bundle_id=BUNDLE, kill_existing=False, start_suspended=True)
        print(f"pid {pid}", flush=True)

        for port in (12345,):
            await attempt(dvt, "requestConnectionAtPort:", (port,), "int-port")
            await attempt(dvt, "requestConnectionAtPort:", (str(port),), "str-port")
            await attempt(dvt, "requestConnectionAtPort:", (f"{host_addr}:{port}",), "addr:port")
            await attempt(dvt, "attachToProcessWithIdentifier:", (pid,), "attach-pid")
            await attempt(dvt, "debuggerPortForProcess:", (pid,), "debugger-port")
            await attempt(
                dvt,
                "launchSuspendedProcessWithDevicePath:bundleIdentifier:environment:arguments:options:",
                ("", BUNDLE, {}, [], {"StartSuspendedKey": True, "KillExisting": False}),
                "launch",
            )


if __name__ == "__main__":
    asyncio.run(main())

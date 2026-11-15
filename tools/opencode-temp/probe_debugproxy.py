#!/usr/bin/env python3
"""Raw probe of the device debugproxy: does it answer a gdb-remote handshake,
and how long does it take?"""
import asyncio
import socket
import sys
import time

from pymobiledevice3.remote import userspace_tunnel
from pymobiledevice3.tcp_forwarder import LockdownTcpForwarder

UDID = "REDACTED_DEVICE_ID"
DEBUGPROXY = "com.apple.internal.dt.remote.debugproxy"
PORT = 12346


async def main():
    rsd = await userspace_tunnel.establish_userspace_rsd(serial=UDID)
    listening = asyncio.Event()
    fwd = LockdownTcpForwarder(rsd, PORT, DEBUGPROXY, listening_event=listening)
    task = asyncio.create_task(fwd.start())
    await asyncio.wait_for(listening.wait(), 30)
    print(f"forwarded on {PORT}", flush=True)

    for attempt in range(3):
        t0 = time.time()
        try:
            s = socket.create_connection(("127.0.0.1", PORT), timeout=40)
            print(f"[{attempt}] TCP connected in {time.time()-t0:.2f}s", flush=True)
            s.settimeout(40)
            pkt = b"$qHostInfo#2c"
            s.sendall(pkt)
            print(f"[{attempt}] sent {pkt!r}", flush=True)
            data = s.recv(4096)
            print(f"[{attempt}] reply after {time.time()-t0:.2f}s: {data!r}", flush=True)
            s.close()
        except Exception as e:
            print(f"[{attempt}] ERROR after {time.time()-t0:.2f}s: {e!r}", flush=True)
        time.sleep(1)

    fwd.stop()
    await asyncio.gather(task, return_exceptions=True)


if __name__ == "__main__":
    asyncio.run(main())

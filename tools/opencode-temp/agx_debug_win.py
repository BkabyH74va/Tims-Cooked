#!/usr/bin/env python3
"""Windows-friendly replacement for `pymobiledevice3 developer debugserver lldb`.

pymobiledevice3's own launcher drives lldb through a Unix pty, which does not
exist on Windows.  This script performs the same steps but spawns lldb.exe as a
normal subprocess, and inserts a byte relay in front of the device's
debugserver so that protocol quirks can be repaired without touching the
device.

It drives the already-installed, dev-signed AGXProbe app -- no Xcode/Mac and
no new binary required.

===========================================================================
PROTOCOL DISCOVERIES (all established by reading the raw bytes on the wire)
===========================================================================

1. `vAttach` must be the VERY FIRST packet.
   The device's debugserver only honours `vAttach;<hexpid>` when it is the
   first gdb-remote packet on a fresh connection.  It then stops the target and
   returns `$T11thread:<tid>;...` (0x11 = SIGSTOP on Darwin).  If *any* query
   precedes it (qHostInfo, qSupported, ...) the device ignores every later
   attach packet while still answering ordinary queries -- which is what made
   this look like "the debugserver has no target-selection mechanism".

2. Two handshake packets break LLDB's parser and are rewritten to `qHostInfo`:
     * `QStartNoAckMode`  -> device stops computing real checksums (all `#00`)
     * `QEnableCompression:type:zlib-deflate;` -> device switches to `$N...`
       framing that LLDB's DecompressPacket() mangles

3. Killing pid discovery the wrong way *causes* the bare-iron fallback.
   LLDB's GetCurrentProcessID() does, in order:
       qProcessInfo -> qC -> qfThreadInfo/qsThreadInfo
   and GetCurrentProcessAndThreadIDs() finishes with
       if ((resp.IsUnsupportedResponse() || resp.IsNormalResponse())
           && ids.empty() && IsConnected())
         ids.emplace_back(1, 1);            // "bare iron" -> pid = tid = 1
   So *forwarding* a pid query to the device and letting it answer with the
   empty `$#00` ("unsupported") packet is exactly what produces pid 1.  Those
   queries must be answered locally, never forwarded.

4. Two ways to reach a usable `process connect`, selected by AGX_MODE:

   AGX_MODE=stopped  (default; this is the one that gives a usable inferior)
       Leave qProcessInfo / qC / qfThreadInfo alone so LLDB learns the real
       pid and thread list.  Then `process connect` takes the "we have a
       valid process" branch:
           SetID(pid); GetThreadList(); GetStopReply(); SetThreadStopInfo()
       The device answers `?` with an empty packet, because the stop event was
       already consumed by the vAttach reply.  The relay therefore caches the
       `$T11...` stop packet from the injected vAttach and substitutes it for
       the empty reply to `?`.  Result: eStateStopped with a real pid and
       thread list -> `expression` works.

   AGX_MODE=connected (fallback)
       Answer qProcessInfo / qC / qfThreadInfo / qsThreadInfo locally with
       `$E01` and never forward them.  GetCurrentProcessID() then returns
       LLDB_INVALID_PROCESS_ID and DoConnectRemote() takes the
       "connected, no inferior" path with no stop-reply check at all.
       `process connect` succeeds, but there is no inferior to evaluate
       expressions in.

5. Response correlation must be type-aware AND hidden-aware.
   LLDB pipelines some requests and the device may place several replies in
   one TCP chunk.  The injected vAttach is registered as a HIDDEN request:
   it may only ever consume a stop-type (`$T`/`$S`) reply, and its reply is
   cached rather than delivered.  A hidden request must never swallow an
   unrelated `$OK`/`$E...`/`$m...` reply.

===========================================================================
TRANSPORT
===========================================================================

* RSD service: `com.apple.internal.dt.remote.debugproxy` (raw gdb-remote).
  `start_lockdown_service()` hangs on it -- use
  `start_lockdown_service_without_checkin()`.
* pymobiledevice3's LockdownTcpForwarder delivers no bytes for this service;
  a custom relay is required (this file).
* LLDB must be spawned with asyncio.create_subprocess_exec, `-b`, and
  stdin=DEVNULL; a blocking parent event loop starves the relay.
"""
import asyncio
import os
import re
import sys

from pymobiledevice3.remote import userspace_tunnel
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl

UDID = "REDACTED_DEVICE_ID"
BUNDLE = "com.nianticlabs.pokemongo.4L9HF29JJU"
DEBUGPROXY = "com.apple.internal.dt.remote.debugproxy"
LLDB = r"G:/REPO\tools\opencode-temp\llvm\llvm\bin\lldb.exe"
PORT = 12345

# "stopped" (default) or "connected" -- see the module docstring, section 4.
MODE = os.environ.get("AGX_MODE", "stopped").strip().lower()

# Handshake packets rewritten to $qHostInfo to keep the device in plain ack mode.
HANDSHAKE_REWRITES = [
    (re.compile(rb"QStartNoAckMode"), b"qHostInfo"),
    (re.compile(rb"QEnableCompression:type:[^#]*"), b"qHostInfo"),
]

# In "connected" mode these are answered locally and never sent to the device.
PID_QUERIES = [
    re.compile(rb"qProcessInfo"),
    re.compile(rb"qC"),
    re.compile(rb"qfThreadInfo"),
    re.compile(rb"qsThreadInfo"),
]
SYNTH_E01 = b"$E01#a6"


def cksum(body: bytes) -> bytes:
    return b"%02x" % (sum(body) & 0xFF)


def frame(body: bytes) -> bytes:
    return b"$" + body + b"#" + cksum(body)


def gdb_pkt(body: str) -> bytes:
    return frame(body.encode())


def req_type(body: bytes) -> str:
    if body.startswith(b"qfThreadInfo") or body.startswith(b"qsThreadInfo"):
        return "threads"
    if body.startswith(b"?"):
        return "stop"
    if body.startswith(b"vCont") or body.startswith(b"vAttach"):
        return "stop"
    return "any"


def resp_type(body: bytes) -> str:
    if body.startswith(b"m") or body.startswith(b"l"):
        return "threads"
    if body.startswith(b"T") or body.startswith(b"S"):
        return "stop"
    return "any"


class Req:
    __slots__ = ("body", "rtype", "hidden", "synth", "resp")

    def __init__(self, body, rtype, hidden=False, synth=None):
        self.body = body
        self.rtype = rtype
        self.hidden = hidden
        self.synth = synth
        self.resp = None

    def done(self):
        return self.synth is not None or self.resp is not None


class Session:
    """Ordered request/response model for one relayed connection.

    Bytes to LLDB are produced *only* by flush(), which emits the resolved
    prefix of the pending queue in request order.  That guarantees LLDB never
    sees a reply before an earlier request's reply, no matter how the device
    batches its packets.
    """

    def __init__(self):
        self.pending: list[Req] = []
        self.stop_reply: bytes | None = None
        self.stop_used = False

    def add(self, body: bytes, hidden=False, synth=None) -> Req:
        r = Req(body, req_type(body), hidden=hidden, synth=synth)
        self.pending.append(r)
        return r

    def match(self, rtype: str) -> Req | None:
        for r in self.pending:
            if r.done():
                continue
            if r.hidden:
                # A hidden request may only consume a stop reply.
                if rtype == "stop":
                    return r
                continue
            if rtype == "any" or r.rtype == rtype or r.rtype == "any":
                return r
        return None

    def resolve(self, body: bytes) -> bool:
        r = self.match(resp_type(body))
        if r is None:
            return False
        if r.hidden:
            self.stop_reply = body
            print(f"== cached stop reply ({len(body)}B) ==", flush=True)
        r.resp = body
        return True

    def flush(self) -> bytes:
        out = bytearray()
        while self.pending and self.pending[0].done():
            r = self.pending.pop(0)
            if r.synth is not None:
                out += r.synth
                continue
            if r.hidden:
                continue
            body = r.resp
            if (
                r.body == b"?"
                and body[:1] not in (b"T", b"S")
                and self.stop_reply is not None
                and not self.stop_used
            ):
                body = self.stop_reply
                self.stop_used = True
                print("== [down] substituted cached stop reply for '?' ==", flush=True)
            out += frame(body)
        return bytes(out)


class UpFilter:
    """lldb -> device: parse packets, rewrite handshake packets, register
    requests, and drop locally-answered pid queries in 'connected' mode."""

    def __init__(self, session: Session):
        self.buf = b""
        self.session = session

    def feed(self, data: bytes) -> bytes:
        self.buf += data
        out = bytearray()
        while self.buf:
            c = self.buf[0]
            if c in (0x2B, 0x2D, 0x03):  # '+', '-', ^C
                out += self.buf[:1]
                self.buf = self.buf[1:]
                continue
            if c == 0x25:  # '%' notification
                h = self.buf.find(b"#")
                if h < 0 or len(self.buf) < h + 3:
                    break
                out += self.buf[: h + 3]
                self.buf = self.buf[h + 3:]
                continue
            if c != 0x24:  # not '$'
                h = self.buf.find(b"$")
                if h < 0:
                    out += self.buf
                    self.buf = b""
                    break
                out += self.buf[:h]
                self.buf = self.buf[h:]
                continue
            h = self.buf.find(b"#")
            if h < 0 or len(self.buf) < h + 3:
                break  # incomplete packet, wait for more bytes
            body = self.buf[1:h]
            original = self.buf[: h + 3]
            self.buf = self.buf[h + 3:]

            newbody, drop, synth = self._rewrite(body)
            if drop:
                self.session.add(body, synth=synth)
                print(
                    f"== [up] dropped ${body.decode(errors='replace')} "
                    f"(answered locally) ==",
                    flush=True,
                )
            elif newbody != body:
                self.session.add(newbody)
                out += frame(newbody)
                print(
                    f"== [up] rewrote ${body.decode(errors='replace')} -> "
                    f"${newbody.decode(errors='replace')} ==",
                    flush=True,
                )
            else:
                self.session.add(body)
                out += original
        return bytes(out)

    @staticmethod
    def _rewrite(body: bytes):
        for rx, repl in HANDSHAKE_REWRITES:
            if rx.fullmatch(body):
                return repl, False, None
        if MODE == "connected":
            for rx in PID_QUERIES:
                if rx.fullmatch(body):
                    return body, True, SYNTH_E01
        return body, False, None


class DownFilter:
    """device -> lldb: parse packets and resolve them against the request
    queue.  Emits nothing itself; Session.flush() produces the LLDB bytes."""

    def __init__(self, session: Session):
        self.buf = b""
        self.session = session
        self.orphans: list[bytes] = []

    def feed(self, data: bytes) -> bytes:
        self.buf += data
        out = bytearray()
        while self.buf:
            c = self.buf[0]
            if c in (0x2B, 0x2D, 0x03):  # '+', '-', ^C
                out += self.buf[:1]
                self.buf = self.buf[1:]
                continue
            if c == 0x25:  # '%' notification
                h = self.buf.find(b"#")
                if h < 0 or len(self.buf) < h + 3:
                    break
                out += self.buf[: h + 3]
                self.buf = self.buf[h + 3:]
                continue
            if c != 0x24:  # not '$'
                h = self.buf.find(b"$")
                if h < 0:
                    out += self.buf
                    self.buf = b""
                    break
                out += self.buf[:h]
                self.buf = self.buf[h:]
                continue
            h = self.buf.find(b"#")
            if h < 0 or len(self.buf) < h + 3:
                break  # incomplete packet, wait for more bytes
            body = self.buf[1:h]
            self.buf = self.buf[h + 3:]

            if not self.session.resolve(body):
                print(
                    f"== [down] orphan ${body[:60].decode(errors='replace')} ==",
                    flush=True,
                )
                self.orphans.append(body)
            else:
                # A late packet may now satisfy an older request.
                self._drain_orphans()
        return bytes(out)

    def _drain_orphans(self):
        changed = True
        while changed and self.orphans:
            changed = False
            for i, body in enumerate(self.orphans):
                if self.session.resolve(body):
                    self.orphans.pop(i)
                    changed = True
                    break


class DebugProxyForwarder:
    """Local TCP listener piping each connection to the device's debugproxy
    RSD service, injecting `vAttach;<hexpid>` as the first gdb-remote packet."""

    def __init__(self, rsd, port, service_name, attach_pid_hex: str):
        self.rsd = rsd
        self.port = port
        self.service_name = service_name
        self.attach_pid_hex = attach_pid_hex
        self.server = None

    async def start(self):
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", self.port)
        print(f"== listening on 127.0.0.1:{self.port} ==", flush=True)

    async def _handle(self, local_reader, local_writer):
        peer = local_writer.get_extra_info("peername")
        print(f"== incoming local connection from {peer} ==", flush=True)
        try:
            remote = await self.rsd.start_lockdown_service_without_checkin(
                self.service_name
            )
        except Exception as e:  # noqa: BLE001
            print(f"== cannot open {self.service_name}: {e!r} ==", flush=True)
            local_writer.close()
            return
        print(f"== {self.service_name} connected for {peer} ==", flush=True)

        session = Session()
        up = UpFilter(session)
        down = DownFilter(session)

        async def write_local(b: bytes):
            if b:
                local_writer.write(b)
                await local_writer.drain()

        async def write_remote(b: bytes):
            if b:
                remote.writer.write(b)
                await remote.writer.drain()

        # --- vAttach must be the very first packet on the wire ---------------
        attach_body = f"vAttach;{self.attach_pid_hex}".encode()
        session.add(attach_body, hidden=True)
        await write_remote(frame(attach_body))
        print(f"== injected ${attach_body.decode()} as first packet ==", flush=True)

        async def up_loop():
            try:
                while True:
                    data = await local_reader.read(65536)
                    if not data:
                        break
                    await write_remote(up.feed(data))
                    await write_local(session.flush())
            except Exception as e:  # noqa: BLE001
                print(f"== up_loop ended: {e!r} ==", flush=True)

        async def down_loop():
            try:
                while True:
                    data = await remote.reader.read(65536)
                    if not data:
                        break
                    passthrough = down.feed(data)
                    await write_local(passthrough + session.flush())
            except Exception as e:  # noqa: BLE001
                print(f"== down_loop ended: {e!r} ==", flush=True)

        await asyncio.gather(up_loop(), down_loop(), return_exceptions=True)
        try:
            await remote.close()
        except Exception:  # noqa: BLE001
            pass
        try:
            local_writer.close()
            await local_writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass

    def stop(self):
        if self.server is not None:
            self.server.close()


EXTRA_COMMANDS = [
    'command script import "G:/REPO/tools/opencode-temp/agx_sweep_lldb.py"',
    "agxwhere",
    "quit",
]

# AGX_EXTRA="cmd1;cmd2" overrides the default command list (handy for quick tests)
if os.environ.get("AGX_EXTRA"):
    EXTRA_COMMANDS = os.environ["AGX_EXTRA"].split(";")


async def main():
    print(f"== mode: {MODE} ==", flush=True)
    print("== establishing userspace RSD ==", flush=True)
    rsd = await userspace_tunnel.establish_userspace_rsd(serial=UDID)

    async with DvtProvider(rsd) as dvt, ProcessControl(dvt) as pc:
        pid = await pc.process_identifier_for_bundle_identifier(BUNDLE)
        if pid <= 0:
            print("== app not running: launching suspended ==", flush=True)
            pid = await pc.launch(bundle_id=BUNDLE, kill_existing=False, start_suspended=True)
        print(f"== target pid {pid} (hex {pid:x}) ==", flush=True)

        fwd = DebugProxyForwarder(rsd, PORT, DEBUGPROXY, f"{pid:x}")
        await fwd.start()
        port = PORT
        print(f"== debugproxy forwarded to 127.0.0.1:{port} ==", flush=True)

        style = os.environ.get("AGX_CONNECT_STYLE", "connect")
        if style == "gdb":
            commands = [f"gdb-remote 127.0.0.1:{port}"] + EXTRA_COMMANDS
        else:
            commands = [
                "platform select remote-ios",
                "settings set plugin.process.gdb-remote.packet-timeout 10",
                "settings set target.process.stop-on-sharedlibrary-events false",
                f"process connect connect://127.0.0.1:{port}",
            ] + EXTRA_COMMANDS

        args = [LLDB, "-b"]
        for c in commands:
            args += ["-o", c]
        print("== launching lldb ==", flush=True)
        proc = await asyncio.create_subprocess_exec(
            *args, stdin=asyncio.subprocess.DEVNULL
        )
        try:
            rc = await asyncio.wait_for(proc.wait(), 240)
        except asyncio.TimeoutError:
            print("== lldb timed out, killing ==", flush=True)
            proc.kill()
            rc = await proc.wait()
        print(f"== lldb exited rc={rc} ==", flush=True)

        fwd.stop()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

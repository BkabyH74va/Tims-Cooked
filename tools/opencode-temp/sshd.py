#!/usr/bin/env python3
"""SSH server inside Terminal (a-Shell 2.3.2 full) on iOS.

Commands run in-process via a-Shell's ios_system() engine - no fork/exec,
no shell binary.  Start it from the terminal:

    python3 ~/Documents/sshd.py

Then (from the Mac, over USB):

    python3 ~/usbforward.py <udid> 2222 2222   # in one window
    ssh -p 2222 -o StrictHostKeyChecking=no root@127.0.0.1   # password: <redacted>

Or straight over Wi-Fi to the phone's IP on port 2222.
"""
import asyncio
import ctypes
import logging
import os
import socket
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "pylib"))
# a wheel is a zip; zipimport can load asyncssh straight out of it
for _cand in ("asyncssh.whl", "pylib/asyncssh.whl"):
    _p = os.path.join(HERE, _cand)
    if os.path.exists(_p):
        sys.path.insert(0, _p)

LOGFILE = os.path.join(HERE, "sshd.log")


def log(msg):
    try:
        with open(LOGFILE, "a") as fh:
            fh.write(msg + "\n")
            fh.flush()
    except Exception:
        pass


log("--- import start pid=%d python=%s cwd=%s" % (os.getpid(), sys.version.split()[0], os.getcwd()))

PORT = int(os.environ.get("SSHD_PORT", "2222"))
RAW_PORT = int(os.environ.get("SSHD_RAW_PORT", "2223"))
USER = os.environ.get("SSHD_USER", "root")
PASS = os.environ[\"SSH_PASS\"]
KEYFILE = os.path.join(HERE, ".ssh_host_key")

# ---------------------------------------------------------------- execution
_lib = None


def _load():
    global _lib
    if _lib is not None:
        return _lib
    candidates = [None]
    exe = os.path.realpath(sys.executable) if getattr(sys, "executable", None) else ""
    if exe:
        candidates.append(os.path.join(os.path.dirname(exe), "Frameworks",
                                       "ios_system.framework", "ios_system"))
    candidates.append("@executable_path/Frameworks/ios_system.framework/ios_system")
    for c in candidates:
        try:
            lib = ctypes.CDLL(c) if c else ctypes.CDLL(None)
            lib.ios_system.restype = ctypes.c_void_p
            lib.ios_system.argtypes = [ctypes.c_char_p]
            lib.fileno.restype = ctypes.c_int
            lib.fileno.argtypes = [ctypes.c_void_p]
            lib.fclose.restype = ctypes.c_int
            lib.fclose.argtypes = [ctypes.c_void_p]
            _lib = lib
            return lib
        except Exception:
            continue
    return None


def _run_ios_system(cmd):
    lib = _load()
    if lib is None:
        raise RuntimeError("ios_system unavailable")
    fp = lib.ios_system(cmd.encode("utf-8", "surrogateescape"))
    if not fp:
        return ""
    out = []
    try:
        fd = lib.fileno(fp)
        while True:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            out.append(chunk)
    finally:
        lib.fclose(fp)
    return b"".join(out).decode("utf-8", "surrogateescape")


def _run_subprocess(cmd):
    import subprocess
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return (p.stdout or "") + (p.stderr or "")


def run(cmd):
    try:
        return _run_subprocess(cmd)
    except Exception:
        try:
            return _run_ios_system(cmd)
        except Exception:
            return "exec failed: " + traceback.format_exc(limit=1)


# ------------------------------------------------------------------- raw tcp
def raw_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", RAW_PORT))
    srv.listen(8)

    def serve():
        while True:
            try:
                c, addr = srv.accept()
            except Exception:
                log("raw accept error\n" + traceback.format_exc())
                continue
            log("raw accept from %r" % (addr,))
            try:
                c.settimeout(10)
                c.sendall(b"hello from ios raw tcp\r\n")
                data = c.recv(4096)
                log("raw got %r" % (data,))
                c.sendall(b"you said: " + data + b"\r\n")
                c.close()
            except Exception:
                log("raw session error\n" + traceback.format_exc())

    threading = __import__("threading")
    threading.Thread(target=serve, daemon=True).start()
    log("raw listener on 0.0.0.0:%d" % RAW_PORT)


# ---------------------------------------------------------------------- ssh
import asyncssh  # noqa: E402

BANNER = (
    "\r\nTerminal 1.0  -  a-Shell 2.3.2 (full)  -  iOS %s\r\n"
    "commands run in-process via ios_system(); type 'exit' to close\r\n\r\n"
    % (".".join(str(x) for x in sys.version_info[:3]))
)


def _crlf(text):
    return text.replace("\r\n", "\n").replace("\n", "\r\n")


async def session_handler(stdin, stdout, stderr):
    log("session opened")
    chan = getattr(stdout, "channel", None)
    try:
        cmd = chan.get_command() if chan is not None else None
    except Exception:
        cmd = None
    log("session opened cmd=%r" % (cmd,))
    if cmd:
        try:
            out = run(cmd)
        except Exception:
            out = "error: " + traceback.format_exc(limit=1)
        log("exec done cmd=%r bytes=%d" % (cmd, len(out)))
        try:
            stdout.write(_crlf(out))
        except Exception:
            pass
        try:
            chan.exit(0)
        except Exception:
            pass
        log("exec session done: %r" % (cmd,))
        return

    try:
        stdout.write(BANNER)
    except Exception:
        log("banner write failed\n" + traceback.format_exc())
        return

    line = []
    try:
        stdout.write("root@ios:~$ ")
    except Exception:
        pass
    while True:
        try:
            ch = await stdin.read(1)
        except Exception:
            break
        if not ch:
            break
        if ch in ("\r", "\n"):
            try:
                stdout.write("\r\n")
            except Exception:
                break
            cmd = "".join(line).strip()
            line = []
            if cmd in ("exit", "logout", "quit"):
                break
            if cmd:
                try:
                    out = run(cmd)
                except Exception:
                    out = "error: " + traceback.format_exc(limit=1)
                try:
                    stdout.write(_crlf(out))
                except Exception:
                    break
            try:
                stdout.write("root@ios:~$ ")
            except Exception:
                break
        elif ch in ("\x7f", "\b"):
            if line:
                line.pop()
                try:
                    stdout.write("\b \b")
                except Exception:
                    break
        elif ch == "\x03":
            line = []
            try:
                stdout.write("^C\r\nroot@ios:~$ ")
            except Exception:
                break
        elif ch == "\x04":
            break
        elif ch >= " ":
            line.append(ch)
            try:
                stdout.write(ch)
            except Exception:
                break
    try:
        chan.exit(0)
    except Exception:
        pass
    log("session closed")


class Server:
    def connection_made(self, conn):
        log("ssh connection_made peer=%r" % (conn.get_extra_info("peername"),))

    def connection_lost(self, exc):
        log("ssh connection_lost exc=%r" % (exc,))

    def begin_auth(self, username):
        log("begin_auth user=%r" % (username,))
        return True

    def password_auth_supported(self):
        return True

    def public_key_auth_supported(self):
        return False

    def host_based_auth_supported(self):
        return False

    def kbdint_auth_supported(self):
        return False

    def get_allowed_auth_methods(self, username):
        return ["password"]

    def auth_completed(self):
        log("auth completed")

    def validate_password(self, username, password):
        ok = username == USER and password == PASS
        log("validate_password user=%r ok=%r" % (username, ok))
        return ok

    def session_requested(self):
        log("session requested")
        return session_handler


def host_key():
    if os.path.exists(KEYFILE):
        return [KEYFILE]
    key = asyncssh.generate_private_key("ssh-ed25519")
    with open(KEYFILE, "wb") as fh:
        fh.write(key.export_private_key())
    os.chmod(KEYFILE, 0o600)
    return [KEYFILE]


def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("198.51.100.1", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "?"


async def main():
    logging.basicConfig(filename=LOGFILE, level=logging.DEBUG,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    log("asyncssh %s loaded" % asyncssh.__version__)

    # probe execution paths (python was itself launched via ios_system, so
    # nested ios_system calls may deadlock - check which path works)
    try:
        import subprocess
        r = subprocess.run("echo PROBE_SUBPROCESS_OK", shell=True,
                           capture_output=True, text=True, timeout=10)
        log("subprocess probe: rc=%r out=%r err=%r" %
            (r.returncode, r.stdout.strip(), r.stderr.strip()))
    except Exception as e:
        log("subprocess probe FAILED: %r" % (e,))
    try:
        o = run("echo PROBE_IOS_OK")
        log("ios_system probe: out=%r" % (o.strip(),))
    except Exception as e:
        log("ios_system probe FAILED: %r" % (e,))
    raw_server()
    keys = host_key()
    log("host key ready: %s" % keys)
    await asyncssh.create_server(Server, "", PORT,
                                 server_host_keys=keys,
                                 process_factory=None,
                                 encoding="utf-8")
    log("listening on 0.0.0.0:%d user=%s ip=%s" % (PORT, USER, local_ip()))
    print("sshd: listening on 0.0.0.0:%d  (user %s)  wifi ip %s" % (PORT, USER, local_ip()))
    print("sshd: from the Mac over USB:  python3 ~/usbforward.py <udid> 2222 %d" % PORT)
    await asyncio.Event().wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    except Exception:
        log("FATAL\n" + traceback.format_exc())
        traceback.print_exc()

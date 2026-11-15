#!/usr/bin/env python3
"""Pure-python iproxy replacement (usbmuxd port forwarder).

Usage:
  usbforward.py -l                 # list devices (usbmuxd)
  usbforward.py <device_id|udid> <local_port> <device_port>

No libimobiledevice / brew needed; talks the usbmuxd unix-socket protocol.
"""
import os
import plistlib
import socket
import struct
import sys
import threading

SOCK = "/var/run/usbmuxd"
MESSAGE_PLIST = 8


def _send(sock, obj, tag=1):
    body = plistlib.dumps(obj, fmt=plistlib.FMT_XML)
    # macOS 26 usbmuxd reads the 16-byte header in host (little-endian) order.
    sock.sendall(struct.pack("<IIII", 16 + len(body), 1, MESSAGE_PLIST, tag) + body)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("usbmuxd closed connection")
        buf += chunk
    return buf


def _recv(sock):
    hdr = _recv_exact(sock, 16)
    length, _ver, mtype, tag = struct.unpack("<IIII", hdr)
    body = _recv_exact(sock, length - 16) if length > 16 else b""
    if mtype == MESSAGE_PLIST:
        return tag, plistlib.loads(body)
    return tag, body


def _mux():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(SOCK)
    return s


def list_devices():
    s = _mux()
    _send(s, {"MessageType": "ListDevices", "ClientVersionString": "usbforward-1.0",
              "ProgName": "usbforward", "kLibUSBMuxVersion": 3})
    _tag, obj = _recv(s)
    s.close()
    return obj.get("DeviceList", [])


def connect(device_id, port):
    s = _mux()
    _send(s, {"MessageType": "Connect", "ClientVersionString": "usbforward-1.0",
              "ProgName": "usbforward", "kLibUSBMuxVersion": 3,
              "DeviceID": device_id, "PortNumber": port})
    _tag, obj = _recv(s)
    if isinstance(obj, dict) and obj.get("MessageType") == "Result" and obj.get("Number") == 0:
        s.settimeout(None)
        return s
    s.close()
    raise OSError("usbmuxd connect failed: %r" % (obj,))


def _pump(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for x in (a, b):
            try:
                x.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def serve(device_id, lport, dport):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", lport))
    srv.listen(8)
    print("forwarding 127.0.0.1:%d -> device %s:%d" % (lport, device_id, dport), flush=True)
    while True:
        cli, addr = srv.accept()
        try:
            upstream = connect(device_id, dport)
        except Exception as exc:
            print("connect failed: %s" % exc, flush=True)
            cli.close()
            continue
        print("accepted %s:%d" % addr, flush=True)
        threading.Thread(target=_pump, args=(cli, upstream), daemon=True).start()
        threading.Thread(target=_pump, args=(upstream, cli), daemon=True).start()


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-l", "--list"):
        for d in list_devices():
            props = d.get("Properties", {})
            print("%s  %s  %s" % (d.get("DeviceID"), props.get("SerialNumber", "?"),
                                  props.get("ConnectionType", "?")))
        return
    if len(args) != 3:
        print(__doc__)
        sys.exit(2)
    ident, lport, dport = args[0], int(args[1]), int(args[2])
    devid = None
    if ident.isdigit():
        devid = int(ident)
    else:
        for d in list_devices():
            if d.get("Properties", {}).get("SerialNumber") == ident:
                devid = d.get("DeviceID")
                break
    if devid is None:
        sys.exit("device not found in usbmuxd: %s" % ident)
    serve(devid, lport, dport)


if __name__ == "__main__":
    main()

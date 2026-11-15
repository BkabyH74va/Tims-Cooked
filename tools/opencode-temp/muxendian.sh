#!/bin/bash
python3 - <<'PY'
import plistlib, socket, struct

def probe(enc, eol):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect("/var/run/usbmuxd")
    body = plistlib.dumps({"MessageType": "ListDevices", "ClientVersionString": "1.0",
                           "ProgName": "probe", "kLibUSBMuxVersion": 3}, fmt=plistlib.FMT_XML)
    s.sendall(struct.pack(enc, 16+len(body), 1, 8, 1) + body)
    try:
        data = s.recv(65536)
        print("%s -> %d bytes %r" % (eol, len(data), data[:120]))
    except Exception as e:
        print("%s -> err %s" % (eol, e))
    s.close()

probe(">IIII", "big-endian")
probe("<IIII", "little-endian")
PY
echo DONE

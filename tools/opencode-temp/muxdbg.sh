#!/bin/bash
echo "=== socket ==="
ls -l /var/run/usbmuxd /private/var/run/usbmuxd 2>&1
echo "=== brew ==="
command -v brew || echo "no brew"
echo "=== python3 ==="
python3 -V
echo "=== raw probe ==="
python3 - <<'PY'
import plistlib, socket, struct
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(5)
s.connect("/var/run/usbmuxd")
body = plistlib.dumps({"MessageType": "ListDevices", "ClientVersionString": "1.0",
                       "ProgName": "probe", "kLibUSBMuxVersion": 3}, fmt=plistlib.FMT_XML)
s.sendall(struct.pack(">IIII", 16+len(body), 1, 8, 1) + body)
try:
    data = s.recv(4096)
    print("got %d bytes: %r" % (len(data), data[:200]))
except Exception as e:
    print("recv err", e)
PY
echo DONE

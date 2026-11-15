import sys
sys.path.insert(0, "/Users/USER")
import usbforward

udid = sys.argv[1] if len(sys.argv) > 1 else "150"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 2222

try:
    s = usbforward.connect(udid, port)
    s.settimeout(6)
    print("connected")
    try:
        data = s.recv(200)
    except Exception as e:
        data = ("<recv error: %r>" % (e,))
    print("recv:", data)
    try:
        s.sendall(b"SSH-2.0-probe\r\n")
    except Exception as e:
        print("send error:", e)
    try:
        data = s.recv(200)
    except Exception as e:
        data = ("<recv2 error: %r>" % (e,))
    print("recv2:", data)
    s.close()
except Exception as e:
    print("connect failed:", e)

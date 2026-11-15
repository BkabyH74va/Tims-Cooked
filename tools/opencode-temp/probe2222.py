import importlib.util, socket

spec = importlib.util.spec_from_file_location("uf", "/Users/USER/usbforward.py")
uf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(uf)

for label, fn in (
    ("USB", lambda: uf.connect(150, 2222)),
    ("WIFI", lambda: socket.create_connection(("198.51.100.1", 2222), 6)),
):
    try:
        s = fn()
        s.settimeout(6)
        print(label, "banner:", s.recv(120))
        s.close()
    except Exception as e:
        print(label, "failed:", e)

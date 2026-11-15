#!/bin/bash
python3 - <<'PY'
import sys, importlib.util
spec = importlib.util.spec_from_file_location("uf", "/Users/USER/usbforward.py")
uf = importlib.util.module_from_spec(spec); spec.loader.exec_module(uf)
for port in (62078, 22, 22):
    try:
        s = uf.connect(150, port)
        print("port %d: CONNECTED" % port)
        s.close()
    except Exception as e:
        print("port %d: %s" % (port, e))
PY
echo DONE

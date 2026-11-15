#!/bin/bash
set -u
D=REDACTED_DEVICE_ID
nohup xcrun devicectl device process launch --device $D --console --terminate-existing com.USER_.terminal \
  > /tmp/tw_console2.log 2>&1 &
sleep 15
echo "##### process check"
xcrun devicectl device info processes --device $D 2>/dev/null | grep -i terminal | head -3
echo "##### console log"
tail -12 /tmp/tw_console2.log
echo "##### port 2222"
python3 - <<'PY'
import importlib.util
spec = importlib.util.spec_from_file_location("uf", "/Users/USER/usbforward.py")
uf = importlib.util.module_from_spec(spec); spec.loader.exec_module(uf)
try:
    s = uf.connect(150, 2222); s.settimeout(6)
    print("banner:", s.recv(120)); s.close()
except Exception as e:
    print("failed:", e)
PY

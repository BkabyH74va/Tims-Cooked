#!/bin/bash
set -u
D=REDACTED_DEVICE_ID
echo "verbose" > /dev/null
printf 'cd ~/Documents\npython3 ~/Documents/sshd.py\n' > "$HOME/tw_push/.profile"
xcrun devicectl device copy to --device $D --domain-type appDataContainer \
  --domain-identifier com.USER_.terminal --source "$HOME/tw_push/.profile" --destination Documents/ 2>&1 | tail -2
echo "##### relaunch app"
xcrun devicectl device process launch --device $D --terminate-existing com.USER_.terminal 2>&1 | tail -4
sleep 10
echo "##### probe port 2222 over usbmuxd"
python3 - <<'PY'
import importlib.util, socket
spec = importlib.util.spec_from_file_location("uf", "/Users/USER/usbforward.py")
uf = importlib.util.module_from_spec(spec); spec.loader.exec_module(uf)
try:
    s = uf.connect(150, 2222)
    s.settimeout(6)
    print("banner:", s.recv(120))
    s.close()
except Exception as e:
    print("connect/banner failed:", e)
PY

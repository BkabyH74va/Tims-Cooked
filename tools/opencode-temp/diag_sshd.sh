#!/bin/bash
set -u
D=REDACTED_DEVICE_ID
xcrun devicectl device copy to --device $D --domain-type appDataContainer \
  --domain-identifier com.USER_.terminal --source "$HOME/tw_push/sshd.py" --destination Documents/ 2>&1 | tail -1
xcrun devicectl device process launch --device $D --terminate-existing com.USER_.terminal 2>&1 | tail -2
sleep 12
echo "##### pull sshd.log"
rm -f "$HOME/sshd.log.pull"
xcrun devicectl device copy from --device $D --domain-type appDataContainer \
  --domain-identifier com.USER_.terminal --source Documents/sshd.log --destination "$HOME/sshd.log.pull" 2>&1 | tail -2
cat "$HOME/sshd.log.pull" 2>/dev/null || echo "(no log pulled)"
echo "##### probe 2222"
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

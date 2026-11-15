#!/bin/bash
set -u
D=REDACTED_DEVICE_ID
printf 'echo "profile $(date)" > ~/Documents/boot.log\npython3 /usr/local/sshd/sshd.py >> ~/Documents/boot.log 2>&1\n' > "$HOME/tw_push/profile_boot"
echo "##### push .profile"
xcrun devicectl device copy to --device $D --domain-type appDataContainer \
  --domain-identifier com.USER_.terminal --source "$HOME/tw_push/profile_boot" --destination Documents/.profile 2>&1 | tail -2
echo "##### relaunch"
xcrun devicectl device process launch --device $D --terminate-existing com.USER_.terminal 2>&1 | tail -2
sleep 14
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
echo "##### pull boot.log"
rm -f "$HOME/boot.pull"
xcrun devicectl device copy from --device $D --domain-type appDataContainer \
  --domain-identifier com.USER_.terminal --source Documents/boot.log --destination "$HOME/boot.pull" 2>&1 | tail -2
cat "$HOME/boot.pull" 2>/dev/null || echo "(no boot.log)"

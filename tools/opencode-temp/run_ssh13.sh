#!/bin/bash
UDID=REDACTED_DEVICE_ID
pkill -f "usbforward.py $UDID" 2>/dev/null
sleep 0.5
nohup python3 "$HOME/usbforward.py" "$UDID" 2222 22 >/tmp/ish_forward.log 2>&1 &
sleep 1
echo "=== forwarder log ==="
cat /tmp/ish_forward.log
echo "=== probe 127.0.0.1:2222 ==="
if nc -z -G 3 -w 3 127.0.0.1 2222; then
  echo "OPEN - trying ssh"
  /usr/bin/expect -f - <<'EXP'
set timeout 15
spawn ssh -tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no \
  -p 2222 root@127.0.0.1 "uname -a; neofetch --stdout"
expect {
  -re "(?i)password" { send "alpine\r"; exp_continue }
  eof
}
EXP
else
  echo "CLOSED - nothing listening on device port 22"
fi
echo "=== forwarder log after ==="
cat /tmp/ish_forward.log
pkill -f "usbforward.py $UDID" 2>/dev/null
echo DONE

#!/bin/bash
D=REDACTED_DEVICE_ID
PID=$(xcrun devicectl device info processes --device $D 2>/dev/null | grep Terminal | head -1 | awk '{print $1}')
echo "killing pid=$PID"
if [ -n "$PID" ]; then
  xcrun devicectl device process terminate --device $D --pid $PID --kill
fi
sleep 4
echo "procs_after_kill=$(xcrun devicectl device info processes --device $D 2>/dev/null | grep -c Terminal)"
echo "--- pre-launch banner test ---"
python3 /tmp/banner_test.py 198.51.100.1 2222 || echo "PORT_CLOSED"
echo "--- launching app ---"
xcrun devicectl device process launch --device $D com.USER_.terminal
sleep 13
rm -f /tmp/boot6.pull
xcrun devicectl device copy from --device $D --domain-type appDataContainer --domain-identifier com.USER_.terminal --source Documents/boot.log --destination /tmp/boot6.pull >/dev/null 2>&1
echo "----- boot.log -----"
cat /tmp/boot6.pull
echo "----- end boot.log -----"
echo "--- post-launch banner test ---"
python3 /tmp/banner_test.py 198.51.100.1 2222

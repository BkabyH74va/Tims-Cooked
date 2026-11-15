#!/bin/bash
D=REDACTED_DEVICE_ID
xcrun devicectl device copy to --device $D --domain-type appDataContainer --domain-identifier com.USER_.terminal --source ~/tw_push/sshd.py --destination Documents/sshd.py && echo sshd-pushed
PID=$(xcrun devicectl device info processes --device $D 2>/dev/null | grep Terminal | head -1 | awk '{print $1}')
echo "pid=$PID"
[ -n "$PID" ] && xcrun devicectl device process terminate --device $D --pid $PID --kill >/dev/null 2>&1
sleep 3
echo "procs=$(xcrun devicectl device info processes --device $D 2>/dev/null | grep -c Terminal)"
xcrun devicectl device process launch --device $D com.USER_.terminal >/dev/null 2>&1
echo relaunched
sleep 12
echo "=== banner test ==="
python3 /tmp/banner_test.py 198.51.100.1 2222 || echo PORT_CLOSED

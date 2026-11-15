#!/bin/bash
D=REDACTED_DEVICE_ID
PID=$(xcrun devicectl device info processes --device $D 2>/dev/null | grep Terminal | awk '{print $1}')
echo "pid=$PID"
[ -n "$PID" ] && xcrun devicectl device process terminate --device $D --pid $PID --kill
sleep 3
echo "procs=$(xcrun devicectl device info processes --device $D 2>/dev/null | grep -c Terminal)"

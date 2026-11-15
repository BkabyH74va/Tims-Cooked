#!/bin/bash
D=REDACTED_DEVICE_ID
PID=$(xcrun devicectl device info processes --device $D 2>/dev/null | grep Terminal | head -1 | cut -c1-6)
echo "pid=$PID"
[ -n "$PID" ] && xcrun devicectl device process terminate --device $D --pid $PID --kill
sleep 3
echo "procs_before_launch=$(xcrun devicectl device info processes --device $D 2>/dev/null | grep -c Terminal)"
xcrun devicectl device process launch --device $D com.USER_.terminal
sleep 15
echo "procs_after=$(xcrun devicectl device info processes --device $D 2>/dev/null | grep -c Terminal)"
python3 /tmp/banner_test.py

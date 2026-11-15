#!/bin/bash
D=REDACTED_DEVICE_ID
echo "=== copying sshd files to 17 Pro"
xcrun devicectl device copy to --device $D --domain-type appDataContainer --domain-identifier com.USER_.terminal --source ~/tw_push/sshd.py --destination Documents/sshd.py && echo sshd-copied
xcrun devicectl device copy to --device $D --domain-type appDataContainer --domain-identifier com.USER_.terminal --source ~/tw_push/asyncssh.whl --destination Documents/asyncssh.whl && echo whl-copied
printf 'python3 ~/Documents/sshd.py >> ~/Documents/boot.log 2>&1\n' > /tmp/newprof17
xcrun devicectl device copy to --device $D --domain-type appDataContainer --domain-identifier com.USER_.terminal --source /tmp/newprof17 --destination Documents/.profile && echo profile-copied
echo "=== restarting 17 Pro Terminal"
PID=$(xcrun devicectl device info processes --device $D 2>/dev/null | grep Terminal | head -1 | awk '{print $1}')
echo "pid=$PID"
[ -n "$PID" ] && xcrun devicectl device process terminate --device $D --pid $PID --kill
sleep 4
echo "procs=$(xcrun devicectl device info processes --device $D 2>/dev/null | grep -c Terminal)"
xcrun devicectl device process launch --device $D com.USER_.terminal
sleep 13
echo "=== verifying files on 17 Pro"
rm -f /tmp/verify17/*
mkdir -p /tmp/verify17
xcrun devicectl device copy from --device $D --domain-type appDataContainer --domain-identifier com.USER_.terminal --source Documents/sshd.py --destination /tmp/verify17/ >/dev/null 2>&1
ls -l /tmp/verify17/sshd.py 2>/dev/null && grep -c PROBE /tmp/verify17/sshd.py
xcrun devicectl device copy from --device $D --domain-type appDataContainer --domain-identifier com.USER_.terminal --source Documents/asyncssh.whl --destination /tmp/verify17/ >/dev/null 2>&1
ls -l /tmp/verify17/asyncssh.whl 2>/dev/null

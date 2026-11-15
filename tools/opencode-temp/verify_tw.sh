#!/bin/bash
set -u
D=REDACTED_DEVICE_ID
APP="$HOME/tw_work/Payload/Terminal.app"
echo "##### .profile support in binary?"
strings -a "$APP/Terminal" 2>/dev/null | grep -nE "^\.profile$|\.a-shell/|startup" | head -10
echo "##### launch (console, background)"
nohup xcrun devicectl device process launch --device $D --console com.USER_.terminal > /tmp/tw_c3.log 2>&1 &
sleep 14
echo "##### process"
xcrun devicectl device info processes --device $D 2>/dev/null | grep -i terminal | head -3
echo "##### console tail"
tail -6 /tmp/tw_c3.log
echo "##### pull container"
rm -rf "$HOME/tw_after"; xcrun devicectl device copy from --device $D --domain-type appDataContainer \
  --domain-identifier com.USER_.terminal --source Documents/ --destination "$HOME/tw_after/" 2>&1 | tail -2
ls -1 "$HOME/tw_after" 2>/dev/null | head

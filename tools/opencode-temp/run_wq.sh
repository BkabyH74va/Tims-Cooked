#!/bin/zsh
UDID=REDACTED_DEVICE_ID
APP=/tmp/worse_query/.build/Build/Products/Debug-iphoneos/worse_query.app
BID=com.USER_.worsequery

echo "===== DEVICES ====="
xcrun devicectl list devices 2>&1 | grep -i "iphone\|udid\|00008110" 

echo "===== INSTALL ====="
xcrun devicectl device install app --device $UDID "$APP" 2>&1 | tail -15

echo "===== LAUNCH ====="
xcrun devicectl device process launch --device $UDID --terminate-existing $BID 2>&1 | tail -15

sleep 10

echo "===== PULL LOG ====="
rm -f /tmp/wq_proof_secondary.log
xcrun devicectl device copy from --device $UDID --domain-type appDataContainer --domain-identifier $BID --source Documents/wq_proof.log --destination /tmp/wq_proof_secondary.log 2>&1 | tail -10

echo "===== LOG CONTENTS ====="
cat /tmp/wq_proof_secondary.log 2>&1

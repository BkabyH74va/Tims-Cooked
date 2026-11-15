#!/bin/bash
DEV=REDACTED_DEVICE_ID
BID=com.nianticlabs.pokemongo.4L9HF29JJU
LOG=geom7.log
cd ~/agx-probe-project || exit 1

security unlock-keychain -p "$KEYCHAIN_PW" "$HOME/Library/Keychains/login.keychain-db" || { echo "UNLOCK_FAILED"; exit 3; }
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PW" "$HOME/Library/Keychains/login.keychain-db" >/dev/null 2>&1

echo "=== build ==="
xcodebuild -project AGXProbe.xcodeproj -scheme AGXProbe -configuration Debug \
  -destination "id=$DEV" -derivedDataPath .build -allowProvisioningUpdates build > /tmp/build8.log 2>&1
RC=$?
if [ $RC -ne 0 ]; then grep -nE 'error:' /tmp/build8.log | head -20; echo "BUILD_FAILED rc=$RC"; exit $RC; fi
echo "BUILD_SUCCEEDED"

APP=.build/Build/Products/Debug-iphoneos/AGXProbe.app
echo "=== install ==="
xcrun devicectl device install app --device "$DEV" "$APP" 2>&1 | grep -E 'bundleID|installed|ERROR' | head -5
echo "=== launch ==="
xcrun devicectl device process launch --device "$DEV" --terminate-existing "$BID" --autorun 2>&1 | tail -6
sleep 15
echo "=== copy log ==="
rm -f /tmp/$LOG
xcrun devicectl device copy from --device "$DEV" \
  --domain-type appDataContainer --domain-identifier "$BID" \
  --source Documents/$LOG --destination /tmp/$LOG 2>&1 | tail -2
echo "=== $LOG ==="
if [ -f /tmp/$LOG ]; then cat /tmp/$LOG; else echo "NO LOG FILE"; fi
echo "=== device state ==="
xcrun devicectl device info details --device "$DEV" 2>&1 | grep -iE 'state|boot' | head -5

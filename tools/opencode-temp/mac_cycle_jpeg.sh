#!/bin/bash
cd ~/agx-probe-project || exit 1
DEV=REDACTED_DEVICE_ID
BID=com.nianticlabs.pokemongo.4L9HF29JJU
APP=.build/Build/Products/Debug-iphoneos/AGXProbe.app
echo "=== kill resident AGXProbe ==="
PID=$(xcrun devicectl device info processes --device "$DEV" --json-output - 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
for p in d.get('processes', []):
    if 'AGXProbe' in p.get('executablePath', ''):
        print(p.get('pid', ''))
" | head -1)
if [ -n "$PID" ]; then
    echo "killing PID $PID"
    xcrun devicectl device process terminate --device "$DEV" --pid "$PID" --kill 2>&1 | tail -2
    sleep 2
fi
echo "=== clean derivedData ==="
rm -rf ~/agx-probe-project/.build
echo "=== BUILD (keychain unlock) ==="
security unlock-keychain -p "$KEYCHAIN_PW" "$HOME/Library/Keychains/login.keychain-db" || { echo UNLOCK_FAILED; exit 3; }
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PW" "$HOME/Library/Keychains/login.keychain-db" >/dev/null 2>&1
xcodebuild -project AGXProbe.xcodeproj -scheme AGXProbe -configuration Debug -destination 'id=REDACTED_DEVICE_ID' -derivedDataPath .build -allowProvisioningUpdates build > /tmp/build22.log 2>&1
echo "BUILD_RC=$?"
grep -cE 'error:' /tmp/build22.log
echo "=== install ==="
xcrun devicectl device install app --device "$DEV" "$APP" 2>&1 | tail -4
echo "=== launch --autorun ==="
xcrun devicectl device process launch --device "$DEV" --terminate-existing "$BID" --autorun 2>&1 | tail -4
echo "=== sleep 90 ==="
sleep 90
echo "=== copy log ==="
rm -f /tmp/reach.log
xcrun devicectl device copy from --device "$DEV" --domain-type appDataContainer --domain-identifier "$BID" --source Documents/reach.log --destination /tmp/reach.log 2>&1 | tail -4
echo "=== reach.log ==="
if [ -f /tmp/reach.log ]; then cat /tmp/reach.log; else echo "NO LOG FILE"; fi
echo "=== SCRIPT END ==="

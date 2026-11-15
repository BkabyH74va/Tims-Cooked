#!/bin/bash
# Same as deploy99 but for the iPhone 17 Pro (iOS 27.0.1 / 24A446).
cd ~/agx-probe-project || exit 1
DEV=REDACTED_DEVICE_ID
BID=com.nianticlabs.pokemongo.4L9HF29JJU
security unlock-keychain -p "$KEYCHAIN_PW" $HOME/Library/Keychains/login.keychain-db >/dev/null 2>&1
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PW" $HOME/Library/Keychains/login.keychain-db >/dev/null 2>&1
xcodebuild -project AGXProbe.xcodeproj -scheme AGXProbe -configuration Debug -destination id=$DEV -derivedDataPath .build17 -allowProvisioningUpdates build > /tmp/b17.log 2>&1
echo BUILD_EXIT=$?
grep -E "error:|BUILD SUCCEEDED|BUILD FAILED" /tmp/b17.log | head -20
APP=.build17/Build/Products/Debug-iphoneos/AGXProbe.app
xcrun devicectl device install app --device $DEV $APP > /tmp/i17.log 2>&1
echo INSTALL_EXIT=$?
tail -3 /tmp/i17.log
xcrun devicectl device process launch --device $DEV --terminate-existing $BID --brotli > /tmp/l17.log 2>&1
echo LAUNCH_EXIT=$?
tail -3 /tmp/l17.log
sleep 45
xcrun devicectl device copy from --device $DEV --domain-type appDataContainer --domain-identifier $BID --source Documents/reach.log --destination /tmp/r17.log > /tmp/c17.log 2>&1
echo COPY_EXIT=$?
echo === LOG ===
cat /tmp/r17.log 2>/dev/null
echo === END ===

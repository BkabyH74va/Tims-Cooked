#!/bin/bash
cd ~/agx-probe-project || exit 1
DEV=REDACTED_DEVICE_ID
BID=com.nianticlabs.pokemongo.4L9HF29JJU
security unlock-keychain -p "$KEYCHAIN_PW" $HOME/Library/Keychains/login.keychain-db >/dev/null 2>&1
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PW" $HOME/Library/Keychains/login.keychain-db >/dev/null 2>&1
xcodebuild -project AGXProbe.xcodeproj -scheme AGXProbe -configuration Debug -destination id=$DEV -derivedDataPath .build13 -allowProvisioningUpdates build > /tmp/b94.log 2>&1
echo BUILD_EXIT=$?
grep -E "error:|BUILD SUCCEEDED|BUILD FAILED" /tmp/b94.log | head -20
APP=.build13/Build/Products/Debug-iphoneos/AGXProbe.app
xcrun devicectl device install app --device $DEV $APP > /tmp/i94.log 2>&1
echo INSTALL_EXIT=$?
tail -5 /tmp/i94.log
xcrun devicectl device process launch --device $DEV --terminate-existing $BID --autorun > /tmp/l94.log 2>&1
echo LAUNCH_EXIT=$?
tail -5 /tmp/l94.log
sleep 22
rm -f /tmp/r94.log
xcrun devicectl device copy from --device $DEV --domain-type appDataContainer --domain-identifier $BID --source Documents/reach.log --destination /tmp/r94.log > /tmp/c94.log 2>&1
echo COPY_EXIT=$?
echo === LOG ===
cat /tmp/r94.log
echo === END ===

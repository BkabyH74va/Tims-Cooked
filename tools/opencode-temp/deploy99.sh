#!/bin/bash
# Build/install/launch AGXProbe with --brotli on the iPhone 13 Pro and pull the log.
cd ~/agx-probe-project || exit 1
DEV=REDACTED_DEVICE_ID
BID=com.nianticlabs.pokemongo.4L9HF29JJU
security unlock-keychain -p "$KEYCHAIN_PW" $HOME/Library/Keychains/login.keychain-db >/dev/null 2>&1
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PW" $HOME/Library/Keychains/login.keychain-db >/dev/null 2>&1
xcodebuild -project AGXProbe.xcodeproj -scheme AGXProbe -configuration Debug -destination id=$DEV -derivedDataPath .build13 -allowProvisioningUpdates build > /tmp/b99.log 2>&1
echo BUILD_EXIT=$?
grep -E "error:|BUILD SUCCEEDED|BUILD FAILED" /tmp/b99.log | head -20
APP=.build13/Build/Products/Debug-iphoneos/AGXProbe.app
xcrun devicectl device install app --device $DEV $APP > /tmp/i99.log 2>&1
echo INSTALL_EXIT=$?
tail -3 /tmp/i99.log
rm -f /tmp/r99.log
# clear the previous log so we only see this run
xcrun devicectl device copy from --device $DEV --domain-type appDataContainer --domain-identifier $BID --source Documents/reach.log --destination /tmp/old99.log > /dev/null 2>&1
xcrun devicectl device process launch --device $DEV --terminate-existing $BID --brotli > /tmp/l99.log 2>&1
echo LAUNCH_EXIT=$?
tail -3 /tmp/l99.log
sleep 45
xcrun devicectl device copy from --device $DEV --domain-type appDataContainer --domain-identifier $BID --source Documents/reach.log --destination /tmp/r99.log > /tmp/c99.log 2>&1
echo COPY_EXIT=$?
echo === LOG ===
cat /tmp/r99.log 2>/dev/null
echo === END ===

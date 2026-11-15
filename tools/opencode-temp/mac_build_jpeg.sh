#!/bin/bash
cd ~/agx-probe-project || exit 1
security unlock-keychain -p "$KEYCHAIN_PW" "$HOME/Library/Keychains/login.keychain-db" || { echo UNLOCK_FAILED; exit 3; }
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PW" "$HOME/Library/Keychains/login.keychain-db" >/dev/null 2>&1
echo "=== BUILD START ==="
xcodebuild -project AGXProbe.xcodeproj -scheme AGXProbe -configuration Debug -destination 'id=REDACTED_DEVICE_ID' -derivedDataPath .build -allowProvisioningUpdates build > /tmp/build11.log 2>&1
echo "BUILD_RC=$?"
grep -nE 'error:' /tmp/build11.log | head -40
echo "=== BUILD END ==="

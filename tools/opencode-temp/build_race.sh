#!/bin/bash
# Build AGXProbe v99 (race harness) for the iPhone 13 Pro.
cd ~/agx-probe-project || exit 1
DEV=REDACTED_DEVICE_ID
security unlock-keychain -p "$KEYCHAIN_PW" "$HOME/Library/Keychains/login.keychain-db" >/dev/null 2>&1
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PW" "$HOME/Library/Keychains/login.keychain-db" >/dev/null 2>&1
xcodebuild -project AGXProbe.xcodeproj -scheme AGXProbe -configuration Debug \
  -destination "id=$DEV" -derivedDataPath .build13 -allowProvisioningUpdates build > /tmp/br99.log 2>&1
echo BUILD_EXIT=$?
grep -E "error:|BUILD SUCCEEDED|BUILD FAILED" /tmp/br99.log | head -40

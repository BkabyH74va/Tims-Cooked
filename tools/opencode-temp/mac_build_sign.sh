#!/bin/bash
# Unlock must happen in the same session as the build (keychain unlock state is
# per security session, not persistent across SSH connections).
security unlock-keychain -p "$KEYCHAIN_PW" "$HOME/Library/Keychains/login.keychain-db" || { echo "UNLOCK_FAILED"; exit 3; }
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PW" "$HOME/Library/Keychains/login.keychain-db" >/dev/null 2>&1
security show-keychain-info "$HOME/Library/Keychains/login.keychain-db" 2>&1

cd ~/agx-probe-project || exit 1
echo "=== build ==="
xcodebuild -project AGXProbe.xcodeproj -scheme AGXProbe -configuration Debug \
  -destination 'id=REDACTED_DEVICE_ID' \
  -derivedDataPath .build \
  -allowProvisioningUpdates build > /tmp/build2.log 2>&1
RC=$?
echo "build_rc=$RC"
grep -nE 'error:|BUILD SUCCEEDED|BUILD FAILED' /tmp/build2.log | head -20
exit $RC

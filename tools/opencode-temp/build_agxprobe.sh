#!/bin/zsh
cd ~/agx-probe-project
security unlock-keychain -p "$KEYCHAIN_PW" "$HOME/Library/Keychains/login.keychain-db" 2>&1 >/dev/null
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PW" "$HOME/Library/Keychains/login.keychain-db" >/dev/null 2>&1
xcodebuild -project AGXProbe.xcodeproj -scheme AGXProbe -configuration Debug -destination "id=REDACTED_DEVICE_ID" -derivedDataPath .build -allowProvisioningUpdates build 2>&1 | grep -E "error:|BUILD SUCCEEDED|BUILD FAILED" | head -30

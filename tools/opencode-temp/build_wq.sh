#!/bin/zsh
security unlock-keychain -p "$KEYCHAIN_PW" "$HOME/Library/Keychains/login.keychain-db"
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PW" "$HOME/Library/Keychains/login.keychain-db" >/dev/null 2>&1
cd /tmp/worse_query
xcodebuild -project worse_query.xcodeproj -scheme worse_query -configuration Debug -destination id=REDACTED_DEVICE_ID -derivedDataPath .build -allowProvisioningUpdates build > /tmp/wq_build.log 2>&1
echo "BUILD_EXIT=$?"
tail -50 /tmp/wq_build.log
ls -la /tmp/worse_query/.build/Build/Products/Debug-iphoneos/ 2>&1

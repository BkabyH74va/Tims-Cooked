#!/bin/sh
date
cd ~/agx-probe-project || exit 1
security unlock-keychain -p "$KEYCHAIN_PW" $HOME/Library/Keychains/login.keychain-db >/dev/null 2>&1
rm -rf .build13/Build/Intermediates.noindex/AGXProbe.build/Debug-iphoneos/AGXProbe.build/Objects-normal/arm64/brotlirepro.* 2>/dev/null
xcodebuild -project AGXProbe.xcodeproj -scheme AGXProbe -configuration Debug -destination id=REDACTED_DEVICE_ID -derivedDataPath .build13 -allowProvisioningUpdates build > /tmp/b100.log 2>&1
echo "BUILD_EXIT=$?"
grep -E "error:|BUILD SUCCEEDED|BUILD FAILED" /tmp/b100.log | head -20
echo "--- file identity ---"
shasum -a 256 AGXProbe/brotlirepro.swift
grep -n '#if' AGXProbe/brotlirepro.swift

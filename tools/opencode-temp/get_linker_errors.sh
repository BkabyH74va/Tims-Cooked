#!/bin/zsh
cd ~/agx-probe-project
xcodebuild -project AGXProbe.xcodeproj -scheme AGXProbe -configuration Debug -destination "id=REDACTED_DEVICE_ID" -derivedDataPath .build -allowProvisioningUpdates build 2>&1 | grep -E "Undefined|duplicate|linker|error:|Undefined symbols" | head -30

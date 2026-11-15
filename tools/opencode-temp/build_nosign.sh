#!/bin/zsh
cd ~/agx-probe-project/SKVLENT-build
rm -rf build
xcodebuild -project SKVLENT.xcodeproj -target Bench27 -configuration Debug \
  CODE_SIGN_IDENTITY="" \
  CODE_SIGNING_REQUIRED=NO \
  CODE_SIGNING_ALLOWED=NO \
  -allowProvisioningUpdates build 2>&1 | tail -20

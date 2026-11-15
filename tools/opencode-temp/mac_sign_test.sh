#!/bin/bash
cd ~/agx-probe-project || exit 1
echo "=== xcent files ==="
find .build -name '*.xcent' 2>/dev/null
echo "=== app contents ==="
ls -la .build/Build/Products/Debug-iphoneos/AGXProbe.app/ 2>&1
echo "=== manual codesign test ==="
APP=.build/Build/Products/Debug-iphoneos/AGXProbe.app
ENT=$(find .build -name 'AGXProbe.app.xcent' | head -1)
echo "ENT=$ENT"
if [ -f "$APP/AGXProbe.debug.dylib" ]; then
  codesign -f -s 3D787264F545F61A7DEABFE375C4C022EA70E25B --timestamp=none --generate-entitlement-der --entitlements "$ENT" "$APP/AGXProbe.debug.dylib" 2>&1
  echo "dylib_sign_exit=$?"
fi
codesign -f -s 3D787264F545F61A7DEABFE375C4C022EA70E25B --timestamp=none --generate-entitlement-der --entitlements "$ENT" "$APP" 2>&1
echo "app_sign_exit=$?"
echo "=== verify ==="
codesign -dv --entitlements - "$APP" 2>&1 | head -30

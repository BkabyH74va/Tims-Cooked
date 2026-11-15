#!/bin/bash
cd ~/agx-probe-project || exit 1
H=3D787264F545F61A7DEABFE375C4C022EA70E25B
APP=.build/Build/Products/Debug-iphoneos/AGXProbe.app
ENT=.build/Build/Intermediates.noindex/AGXProbe.build/Debug-iphoneos/AGXProbe.build/AGXProbe.app.xcent
KC=$HOME/Library/Keychains/login.keychain-db

echo "=== keychain search list ==="
security list-keychains
echo "=== identities ==="
security find-identity -v -p codesigning | head -5

echo "=== (a) plain file, no ent ==="
printf test > /tmp/t_a; codesign -f -s $H /tmp/t_a 2>&1; echo "a=$?"

echo "=== (b) plain file, WITH ent ==="
printf test > /tmp/t_b; codesign -f -s $H --entitlements "$ENT" /tmp/t_b 2>&1; echo "b=$?"

echo "=== (c) app, no ent ==="
cp -R "$APP" /tmp/app_c 2>/dev/null
codesign -f -s $H /tmp/app_c 2>&1; echo "c=$?"

echo "=== (d) app, WITH ent + explicit keychain ==="
cp -R "$APP" /tmp/app_d 2>/dev/null
codesign -f -s $H --keychain "$KC" --entitlements "$ENT" /tmp/app_d 2>&1; echo "d=$?"

echo "=== (e) plain file, WITH ent + explicit keychain ==="
printf test > /tmp/t_e; codesign -f -s $H --keychain "$KC" --entitlements "$ENT" /tmp/t_e 2>&1; echo "e=$?"

echo "=== (f) app, WITH ent, no DER flag ==="
cp -R "$APP" /tmp/app_f 2>/dev/null
codesign -f -s $H --entitlements "$ENT" /tmp/app_f 2>&1; echo "f=$?"

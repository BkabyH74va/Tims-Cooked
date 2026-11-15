#!/bin/bash
cd ~/agx-probe-project || exit 1
APP=.build/Build/Products/Debug-iphoneos/AGXProbe.app
ls -la "$APP"
echo "=== binary strings check ==="
find "$APP" -name 'AGXProbe' -o -name '*.App' -type d | head -5
BIN=$(find "$APP" -maxdepth 2 -type f -perm +111 -name 'AGXProbe' | head -1)
echo "BIN=$BIN"
if [ -n "$BIN" ]; then
  strings "$BIN" | grep -i -E 'AGXProbe v[0-9]|JPEG probe|Run JPEG|v9' | sort -u | head -30
fi
echo "=== script end ==="

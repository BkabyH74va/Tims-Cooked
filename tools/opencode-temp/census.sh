#!/bin/bash
set -u
APP="$HOME/tw_work/Payload/Terminal.app"
echo "##### mach-o census"
find "$APP" -type f \( -perm -111 -o -name "*.dylib" -o -name "*.so" \) -print0 |
  xargs -0 file 2>/dev/null | grep -c "Mach-O"
echo "##### dirs with binaries"
find "$APP" -type f \( -perm -111 -o -name "*.dylib" -o -name "*.so" \) -print0 |
  xargs -0 file 2>/dev/null | grep "Mach-O" | awk -F: '{print $1}' | sed "s|$APP/||" | cut -d/ -f1 | sort | uniq -c
echo "##### profile entitlements"
security cms -D -i "$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles/20eccc84-0a7e-4211-8680-15203ef84d67.mobileprovision" > /tmp/twprof.plist
plutil -extract Entitlements xml1 -o /tmp/twent.plist /tmp/twprof.plist
cat /tmp/twent.plist

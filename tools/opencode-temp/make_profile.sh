#!/bin/bash
set -u
cd /tmp/worse_query
xcodebuild -project worse_query.xcodeproj -scheme worse_query -configuration Debug \
  -destination 'generic/platform=iOS' -allowProvisioningUpdates \
  -derivedDataPath .build_prof PRODUCT_BUNDLE_IDENTIFIER=com.USER_.terminal build \
  > /tmp/prof_build.log 2>&1
echo "exit=$?"
tail -15 /tmp/prof_build.log
echo "##### matching profile"
P="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"
for f in "$P"/*.mobileprovision; do
  d=$(mktemp -d)
  security cms -D -i "$f" > "$d/p.plist" 2>/dev/null || continue
  appid=$(/usr/libexec/PlistBuddy -c "Print :Entitlements:application-identifier" "$d/p.plist" 2>/dev/null)
  case "$appid" in
    *com.USER_.terminal*)
      echo "FOUND $f"
      echo "  appid=$appid"
      echo "  uuid=$(/usr/libexec/PlistBuddy -c "Print :UUID" "$d/p.plist")"
      echo "  name=$(/usr/libexec/PlistBuddy -c "Print :Name" "$d/p.plist")"
      echo "  expiry=$(/usr/libexec/PlistBuddy -c "Print :ExpirationDate" "$d/p.plist")"
      echo "  groups=$(/usr/libexec/PlistBuddy -c "Print :Entitlements:com.apple.security.application-groups" "$d/p.plist" | tr '\n' ' ')"
      echo "  devices=$(/usr/libexec/PlistBuddy -c "Print :ProvisionedDevices" "$d/p.plist" | tr '\n' ' ')"
      ;;
  esac
  rm -rf "$d"
done

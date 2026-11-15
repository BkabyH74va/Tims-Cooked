#!/bin/bash
echo "##### identities"
security find-identity -v -p codesigning 2>&1 | sed -n '1,20p'
echo "##### profiles"
P="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles"
ls -1 "$P" 2>/dev/null | head -40
for f in "$P"/*.mobileprovision; do
  [ -f "$f" ] || continue
  d=$(mktemp -d)
  security cms -D -i "$f" > "$d/p.plist" 2>/dev/null || continue
  name=$(/usr/libexec/PlistBuddy -c "Print :Name" "$d/p.plist" 2>/dev/null)
  uuid=$(/usr/libexec/PlistBuddy -c "Print :UUID" "$d/p.plist" 2>/dev/null)
  appid=$(/usr/libexec/PlistBuddy -c "Print :Entitlements:application-identifier" "$d/p.plist" 2>/dev/null)
  groups=$(/usr/libexec/PlistBuddy -c "Print :Entitlements:com.apple.security.application-groups" "$d/p.plist" 2>/dev/null | tr '\n' ',')
  expiry=$(/usr/libexec/PlistBuddy -c "Print :ExpirationDate" "$d/p.plist" 2>/dev/null)
  echo "NAME=$name | UUID=$uuid | APPID=$appid | GROUPS=$groups | EXP=$expiry"
  rm -rf "$d"
done
echo "##### download status"
ls -l "$HOME/Downloads/Terminal.ipa"

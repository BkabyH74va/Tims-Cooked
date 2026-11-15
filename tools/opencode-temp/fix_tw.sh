#!/bin/bash
set -u
APP="$HOME/tw_work/Payload/Terminal.app"
IDENT="3D787264F545F61A7DEABFE375C4C022EA70E25B"
D=REDACTED_DEVICE_ID
security unlock-keychain -p "$KEYCHAIN_PW" "$HOME/Library/Keychains/login.keychain-db" || exit 1

echo "##### stage sshd into bundle"
mkdir -p "$APP/usr/local/sshd"
cp "$HOME/tw_push/sshd.py" "$APP/usr/local/sshd/sshd.py"
rm -rf "$APP/usr/local/sshd/pylib"
cp -R "$HOME/tw_push/pylib" "$APP/usr/local/sshd/pylib"
ls -1 "$APP/usr/local/sshd" | head
du -sh "$APP/usr/local/sshd"

echo "##### re-sign app seal"
[ -f /tmp/twent.plist ] || { echo "missing entitlements"; exit 1; }
codesign --force --sign "$IDENT" --entitlements /tmp/twent.plist --generate-entitlement-der --timestamp=none "$APP" 2>&1 | tail -2
codesign --verify --strict "$APP" 2>&1 | tail -2
echo "verify rc=$?"

echo "##### reinstall"
xcrun devicectl device uninstall app --device $D com.USER_.terminal 2>&1 | tail -2
xcrun devicectl device install app --device $D "$APP" 2>&1 | tail -6

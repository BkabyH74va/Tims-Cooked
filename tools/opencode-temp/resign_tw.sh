#!/bin/bash
set -u
APP="$HOME/tw_work/Payload/Terminal.app"
IDENT="3D787264F545F61A7DEABFE375C4C022EA70E25B"
PROF="$HOME/Library/Developer/Xcode/UserData/Provisioning Profiles/20eccc84-0a7e-4211-8680-15203ef84d67.mobileprovision"
BID="com.USER_.terminal"
GROUP="group.USER_.worsequery"

echo "[1] strip extensions"
rm -rf "$APP/PlugIns"

echo "[2] Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier $BID" "$APP/Info.plist"
/usr/libexec/PlistBuddy -c "Set :CFBundleDisplayName Terminal" "$APP/Info.plist"
/usr/libexec/PlistBuddy -c "Delete :AppGroupIdentifier" "$APP/Info.plist" 2>/dev/null
/usr/libexec/PlistBuddy -c "Add :AppGroupIdentifier string $GROUP" "$APP/Info.plist"
/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$APP/Info.plist"
/usr/libexec/PlistBuddy -c "Print :AppGroupIdentifier" "$APP/Info.plist"

echo "[3] entitlements"
security cms -D -i "$PROF" > /tmp/twprof.plist
plutil -extract Entitlements xml1 -o /tmp/twent.plist /tmp/twprof.plist
grep -c "<key>" /tmp/twent.plist

echo "[4] drop stale signatures"
find "$APP" -name _CodeSignature -type d -prune -exec rm -rf {} + 2>/dev/null

echo "[5] list mach-o payload"
python3 - "$APP" > /tmp/tw_macho.txt <<'PY'
import os, sys
root = sys.argv[1]
magics = {b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"}
main = os.path.join(root, "Terminal")
for dp, dn, fn in os.walk(root):
    for f in fn:
        p = os.path.join(dp, f)
        if p == main:
            continue
        try:
            with open(p, "rb") as fh:
                if fh.read(4) not in magics:
                    continue
        except OSError:
            continue
        print(p)
PY
wc -l < /tmp/tw_macho.txt

echo "[6] sign payload binaries (parallel)"
tr '\n' '\0' < /tmp/tw_macho.txt | xargs -0 -n 1 -P 8 codesign --force --sign "$IDENT" --timestamp=none 2>&1 | tail -20
echo "payload rc=$?"

echo "[7] sign framework bundles (parallel)"
find "$APP/Frameworks" -type d -name "*.framework" -print0 |
  xargs -0 -n 1 -P 8 codesign --force --sign "$IDENT" --timestamp=none 2>&1 | tail -20
echo "frameworks rc=$?"

echo "[8] sign app"
cp "$PROF" "$APP/embedded.mobileprovision"
codesign --force --sign "$IDENT" --entitlements /tmp/twent.plist --generate-entitlement-der --timestamp=none "$APP"
echo "app rc=$?"
codesign --verify --strict --verbose=2 "$APP" 2>&1 | tail -5
echo "[9] done"
ls -l "$APP/Terminal" "$APP/Frameworks/TerminalSBX.dylib"

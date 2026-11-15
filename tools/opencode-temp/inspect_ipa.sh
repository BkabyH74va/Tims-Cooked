#!/bin/bash
set -u
cd "$HOME"
shasum -a 256 Downloads/Terminal.ipa
rm -rf tw_work && mkdir -p tw_work
cd tw_work
unzip -q "$HOME/Downloads/Terminal.ipa" -d .
echo "##### top level"
ls -la
APP=$(ls -d Payload/*.app | head -1)
echo "APP=$APP"
echo "##### bundle info"
/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$APP/Info.plist"
/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$APP/Info.plist"
/usr/libexec/PlistBuddy -c "Print :CFBundleName" "$APP/Info.plist"
/usr/libexec/PlistBuddy -c "Print :MinimumOSVersion" "$APP/Info.plist" 2>/dev/null
echo "##### app entitlements"
codesign -d --entitlements :- "$APP" 2>/dev/null
echo "##### embedded profile"
security cms -D -i "$APP/embedded.mobileprovision" > /tmp/tw_prof.plist 2>/dev/null
/usr/libexec/PlistBuddy -c "Print :Name" /tmp/tw_prof.plist
/usr/libexec/PlistBuddy -c "Print :TeamIdentifier" /tmp/tw_prof.plist
/usr/libexec/PlistBuddy -c "Print :Entitlements:application-identifier" /tmp/tw_prof.plist
/usr/libexec/PlistBuddy -c "Print :Entitlements:com.apple.security.application-groups" /tmp/tw_prof.plist
echo "provisioned devices:"; /usr/libexec/PlistBuddy -c "Print :ProvisionedDevices" /tmp/tw_prof.plist 2>/dev/null | head -5
echo "##### TerminalSBX"
ls -l "$APP/Frameworks" 2>/dev/null | head -20
file "$APP/Frameworks/TerminalSBX.dylib" 2>/dev/null
codesign -d --entitlements :- "$APP/Frameworks/TerminalSBX.dylib" 2>/dev/null

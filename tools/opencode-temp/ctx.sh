#!/bin/bash
echo "##### /tmp/worse_query present?"
ls -d /tmp/worse_query 2>&1 | head -3
ls -l /tmp/worse_query/worse_query/worse_query.entitlements 2>&1
echo "##### source context around group list"
cd "$HOME/terminal_worse"
grep -n -B25 -A10 'group\.AsheKube' src/TerminalSBX.m | sed -n '1,80p'
echo "##### appex identities"
cd "$HOME/tw_work/Payload/Terminal.app/PlugIns"
for a in *.appex; do
  /usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$a/Info.plist"
  /usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$a/Info.plist"
done
echo "##### appex entitlements"
for a in *.appex; do
  echo "-- $a"
  codesign -d --entitlements :- "$a" 2>/dev/null | tr -d '\n'; echo
done

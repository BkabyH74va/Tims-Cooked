#!/bin/bash
set -u
APP="$HOME/tw_work/Payload/Terminal.app"
echo "##### ios_system framework"
ls -d "$APP/Frameworks"/*ios_system* "$APP/Frameworks"/*IOS* 2>/dev/null
find "$APP" -maxdepth 2 -iname "*ios_system*" | head
echo "##### exports"
for b in "$APP/Frameworks/ios_system.framework/ios_system" "$APP/Frameworks/ios_system.framework/Versions/A/ios_system"; do
  [ -f "$b" ] && { echo "binary: $b"; nm -gU "$b" 2>/dev/null | grep -i "ios_system\|ios_set_streams\|ios_get_last" | head -10; }
done
echo "##### commandDictionary python entries"
grep -A2 -i "python" "$APP/commandDictionary.plist" 2>/dev/null | head -20
echo "##### download asyncssh"
mkdir -p "$HOME/tw_push"
curl -sSL -o "$HOME/tw_push/asyncssh.whl" \
  "https://files.pythonhosted.org/packages/1e/9f/ad61867b12823f6e2c0ef2b80a704273b9385de707ac4539afa445c0665d/asyncssh-2.13.1-py3-none-any.whl"
ls -l "$HOME/tw_push/asyncssh.whl"
rm -rf "$HOME/tw_push/pylib"; mkdir -p "$HOME/tw_push/pylib"
cd "$HOME/tw_push/pylib" && unzip -q ../asyncssh.whl
ls -1 "$HOME/tw_push/pylib" | head

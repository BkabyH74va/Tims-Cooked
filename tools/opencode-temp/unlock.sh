#!/bin/bash
security unlock-keychain -p "$KEYCHAIN_PW" "$HOME/Library/Keychains/login.keychain-db" && echo "unlocked"
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PW" "$HOME/Library/Keychains/login.keychain-db" >/dev/null 2>&1 && echo "partition-list set"
security show-keychain-info "$HOME/Library/Keychains/login.keychain-db" 2>&1
cp /bin/echo /tmp/sigtest
codesign --force --sign 3D787264F545F61A7DEABFE375C4C022EA70E25B --timestamp=none /tmp/sigtest 2>&1
echo "sigtest rc=$?"
codesign -dv /tmp/sigtest 2>&1 | head -3

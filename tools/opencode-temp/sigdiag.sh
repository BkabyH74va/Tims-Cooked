#!/bin/bash
echo "##### resign log summary"
grep -nE "errSec|rc=|failed|^\[[0-9]\]" /tmp/resign_tw.log | head -40
echo "##### keychain state"
security list-keychains
security default-keychain
security show-keychain-info "$HOME/Library/Keychains/login.keychain-db" 2>&1
echo "##### codesign smoke test"
cp /bin/echo /tmp/sigtest
timeout 25 codesign --force --sign 3D787264F545F61A7DEABFE375C4C022EA70E25B --timestamp=none /tmp/sigtest 2>&1
echo "sigtest rc=$?"

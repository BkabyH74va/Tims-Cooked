#!/bin/zsh
cd ~/agx-probe-project/SKVLENT-build
security unlock-keychain -p "$KEYCHAIN_PW" "$HOME/Library/Keychains/login.keychain-db" 2>&1
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$KEYCHAIN_PW" "$HOME/Library/Keychains/login.keychain-db" >/dev/null 2>&1
/usr/bin/codesign -s "Apple Development: redacted@example.invalid (CT2NGWCYS4)" --verbose Bench27.app 2>&1 | tail -20

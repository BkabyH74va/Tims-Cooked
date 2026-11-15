#!/bin/bash
D=REDACTED_DEVICE_ID
rm -rf "$HOME/tw_pull"; mkdir -p "$HOME/tw_pull"
echo "##### pulled container docs"
xcrun devicectl device copy from --device $D --domain-type appDataContainer \
  --domain-identifier com.USER_.terminal --source Documents/ --destination "$HOME/tw_pull/" 2>&1 | tail -5
echo "##### tree"
find "$HOME/tw_pull" -maxdepth 3 | head -40
echo "##### _sandbox contents"
ls -la "$HOME/tw_pull/Documents/_sandbox" 2>&1 | head -25

#!/bin/bash
D=REDACTED_DEVICE_ID
echo "=== 13 Pro: ssh/terminal-ish apps ==="
xcrun devicectl device info apps --device $D 2>/dev/null | grep -iE "ish|shell|term|ssh|putty|newterm|sileo|cydia|filza|bootstrap|jailbreak|dopamine|palera1n|trollstore|neofetch" | head -30
echo "=== 13 Pro: app count ==="
xcrun devicectl device info apps --device $D 2>/dev/null | wc -l
echo "=== 13 Pro: device info ==="
xcrun devicectl device info details --device $D 2>/dev/null | grep -iE "osVersionNumber|buildVersion|productType|marketingName|deviceName" | head -10
echo DONE

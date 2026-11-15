#!/bin/bash
echo "=== usbmuxd log ==="
log show --last 3m --predicate 'process == "usbmuxd"' --style compact 2>/dev/null | tail -25
echo "=== devicectl manage help ==="
xcrun devicectl manage --help 2>&1 | head -30
echo "=== devicectl device help (tunnel?) ==="
xcrun devicectl device --help 2>&1 | grep -iE "tunnel|forward|network|port" | head -20
echo DONE

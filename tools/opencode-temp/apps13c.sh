#!/bin/bash
D=REDACTED_DEVICE_ID
echo "=== iproxy / libimobiledevice present? ==="
command -v iproxy || echo "no iproxy"
command -v idevice_id || echo "no idevice_id"
brew list --formula 2>/dev/null | grep -i -E "imobiledevice|usbmuxd" || echo "no brew libimobiledevice"
echo "=== raw apps output ==="
xcrun devicectl device info apps --device $D 2>&1 | head -25
echo "=== rc=$? ==="
echo DONE

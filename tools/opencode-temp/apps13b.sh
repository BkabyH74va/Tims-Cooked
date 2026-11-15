#!/bin/bash
D=REDACTED_DEVICE_ID
echo "=== raw apps output (first 30 lines) ==="
xcrun devicectl device info apps --device $D 2>&1 | head -30
echo "=== raw details output (first 40 lines) ==="
xcrun devicectl device info details --device $D 2>&1 | head -40
echo DONE

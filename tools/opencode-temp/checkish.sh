#!/bin/bash
D=REDACTED_DEVICE_ID
echo "=== apps on 13 Pro ==="
xcrun devicectl device info apps --device $D 2>&1 | sed -n '1,20p'
echo "=== which expect ==="
command -v expect || echo "no expect"
echo DONE

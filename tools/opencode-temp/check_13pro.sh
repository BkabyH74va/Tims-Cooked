#!/bin/bash
D=REDACTED_DEVICE_ID
echo "Terminal process on 13 Pro:"
xcrun devicectl device info processes --device $D 2>/dev/null | grep Terminal | head -3 || echo "NOT RUNNING"
echo "port 2222 on phone:"
python3 /tmp/banner_test.py 198.51.100.1 2222 || echo "PORT_CLOSED"

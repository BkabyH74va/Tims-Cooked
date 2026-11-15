#!/bin/bash
DEV=REDACTED_DEVICE_ID
echo "=== find AGXProbe PID ==="
PID=$(xcrun devicectl device info processes --device "$DEV" --json-output - 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
for p in d.get('processes', []):
    if 'AGXProbe' in p.get('executablePath', ''):
        print(p.get('pid', ''))
" | head -1)
echo "PID=$PID"
if [ -n "$PID" ]; then
    echo "=== terminating PID $PID ==="
    xcrun devicectl device process terminate --device "$DEV" --pid "$PID" --kill 2>&1
    sleep 2
fi
echo "=== verify gone ==="
xcrun devicectl device info processes --device "$DEV" --json-output - 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
found = [p for p in d.get('processes', []) if 'AGXProbe' in p.get('executablePath', '')]
if found:
    print('STILL RUNNING:', found[0].get('pid'))
else:
    print('not running')
"

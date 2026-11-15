#!/bin/bash
DEV=REDACTED_DEVICE_ID
echo "=== devicectl copy domain types ==="
xcrun devicectl device copy from --help 2>&1 | sed -n '/domain-type/,/^$/p' | head -30
echo
echo "=== device details (full) ==="
xcrun devicectl device info details --device "$DEV" 2>&1 | head -40
echo
echo "=== try systemCrashLogs ==="
rm -rf /tmp/crashlogs; mkdir -p /tmp/crashlogs
xcrun devicectl device copy from --device "$DEV" --domain-type systemCrashLogs \
  --source . --destination /tmp/crashlogs 2>&1 | tail -5
find /tmp/crashlogs -type f 2>/dev/null | head -20

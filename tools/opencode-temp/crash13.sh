#!/bin/bash
DEV=REDACTED_DEVICE_ID
rm -rf /tmp/crash13
mkdir -p /tmp/crash13
xcrun devicectl device copy from --device $DEV --domain-type systemCrashLogs --source . --destination /tmp/crash13 > /tmp/cc13.log 2>&1
echo COPY_EXIT=$?
tail -5 /tmp/cc13.log
echo === FILES ===
ls -lt /tmp/crash13 | head -25
echo === NEWEST IPS/PANIC HEADERS ===
for f in /tmp/crash13/*.ips /tmp/crash13/*.panic; do
  [ -f "$f" ] || continue
  echo "----- $f"
  head -c 1200 "$f"
  echo
done

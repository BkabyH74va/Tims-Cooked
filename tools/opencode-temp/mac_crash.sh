#!/bin/bash
echo "=== candidate crash dirs ==="
ls -d ~/Library/Logs/CrashReporter/MobileDevice/* 2>/dev/null
echo
echo "=== newest .ips / .crash (last 30 min) ==="
find ~/Library/Logs/CrashReporter ~/Library/Developer/Xcode/DeviceDiagnostics -type f \( -name '*.ips' -o -name '*.crash' \) -mmin -60 2>/dev/null | while read f; do
  echo "--- $f"
  head -c 1200 "$f"
  echo
done
echo
echo "=== ipsw available? ==="
command -v ipsw || echo "no ipsw in PATH"
echo "=== devicectl crash command? ==="
xcrun devicectl device --help 2>&1 | grep -i crash | head -5

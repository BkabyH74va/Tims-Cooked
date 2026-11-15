#!/bin/bash
DEV=REDACTED_DEVICE_ID
BID=com.nianticlabs.pokemongo.4L9HF29JJU
sleep 20
echo "=== process check ==="
xcrun devicectl device info processes --device "$DEV" 2>/dev/null | grep -i "$BID" | head -3
echo "=== re-copy log ==="
rm -f /tmp/reach2.log
xcrun devicectl device copy from --device "$DEV" \
  --domain-type appDataContainer --domain-identifier "$BID" \
  --source Documents/reach.log --destination /tmp/reach2.log 2>&1 | tail -2
echo "=== reach.log ==="
if [ -f /tmp/reach2.log ]; then cat /tmp/reach2.log; else echo "NO LOG"; fi
echo "=== device state ==="
xcrun devicectl device info details --device "$DEV" 2>&1 | grep -iE 'state|boot' | head -4

#!/bin/bash
cd ~/agx-probe-project || exit 1
DEV=REDACTED_DEVICE_ID
BID=com.nianticlabs.pokemongo.4L9HF29JJU
APP=.build/Build/Products/Debug-iphoneos/AGXProbe.app

echo "=== install ==="
xcrun devicectl device install app --device "$DEV" "$APP" 2>&1 | tail -15

echo "=== launch ==="
xcrun devicectl device process launch --device "$DEV" --terminate-existing "$BID" --autorun 2>&1 | tail -15

echo "=== wait ==="
sleep 15

echo "=== copy log ==="
rm -f /tmp/geom.log
xcrun devicectl device copy from --device "$DEV" \
  --domain-type appDataContainer --domain-identifier "$BID" \
  --source Documents/geom.log --destination /tmp/geom.log 2>&1 | tail -10

echo "=== geom.log ==="
if [ -f /tmp/geom.log ]; then cat /tmp/geom.log; else echo "NO LOG FILE"; fi

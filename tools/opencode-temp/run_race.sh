#!/bin/bash
# Install + launch v99 --race on the 13 Pro, then pull reach.log.
cd ~/agx-probe-project || exit 1
DEV=REDACTED_DEVICE_ID
BID=com.nianticlabs.pokemongo.4L9HF29JJU
APP=.build13/Build/Products/Debug-iphoneos/AGXProbe.app
xcrun devicectl device install app --device "$DEV" "$APP" > /tmp/i99r.log 2>&1
echo INSTALL_EXIT=$?
tail -4 /tmp/i99r.log
rm -f /tmp/old99r.log
xcrun devicectl device copy from --device "$DEV" --domain-type appDataContainer \
  --domain-identifier "$BID" --source Documents/reach.log --destination /tmp/old99r.log > /dev/null 2>&1
xcrun devicectl device process launch --device "$DEV" --terminate-existing "$BID" --race --iters=300 > /tmp/l99r.log 2>&1
echo LAUNCH_EXIT=$?
tail -4 /tmp/l99r.log
sleep 30
rm -f /tmp/r99r.log
xcrun devicectl device copy from --device "$DEV" --domain-type appDataContainer \
  --domain-identifier "$BID" --source Documents/reach.log --destination /tmp/r99r.log > /tmp/c99r.log 2>&1
echo COPY_EXIT=$?
tail -3 /tmp/c99r.log
if [ -f /tmp/r99r.log ]; then echo "=== reach.log ==="; cat /tmp/r99r.log; else echo "NO LOG"; fi

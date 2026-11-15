#!/bin/bash
# Install + launch v101 --race on the 13 Pro, then pull reach.log.
cd ~/agx-probe-project || exit 1
DEV=REDACTED_DEVICE_ID
BID=com.nianticlabs.pokemongo.4L9HF29JJU
APP=.build13/Build/Products/Debug-iphoneos/AGXProbe.app
xcrun devicectl device install app --device "$DEV" "$APP" > /tmp/i101r.log 2>&1
echo INSTALL_EXIT=$?
tail -4 /tmp/i101r.log
xcrun devicectl device process launch --device "$DEV" --terminate-existing "$BID" --race --iters=50 --reqpool=512 --victims=256 --drains=1 --threads=2 --delay=0 > /tmp/l101r.log 2>&1
echo LAUNCH_EXIT=$?
tail -4 /tmp/l101r.log
sleep 45
rm -f /tmp/r101r.log
xcrun devicectl device copy from --device "$DEV" --domain-type appDataContainer \
  --domain-identifier "$BID" --source Documents/reach.log --destination /tmp/r101r.log > /tmp/c101r.log 2>&1
echo COPY_EXIT=$?
tail -3 /tmp/c101r.log
if [ -f /tmp/r101r.log ]; then echo "=== reach.log ==="; cat /tmp/r101r.log; else echo "NO LOG"; fi

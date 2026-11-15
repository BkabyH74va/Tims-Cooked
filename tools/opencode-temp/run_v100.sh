#!/bin/bash
# Install + launch v100 --race on the 13 Pro, then pull reach.log.
cd ~/agx-probe-project || exit 1
DEV=REDACTED_DEVICE_ID
BID=com.nianticlabs.pokemongo.4L9HF29JJU
APP=.build13/Build/Products/Debug-iphoneos/AGXProbe.app
xcrun devicectl device install app --device "$DEV" "$APP" > /tmp/i100r.log 2>&1
echo INSTALL_EXIT=$?
tail -4 /tmp/i100r.log
rm -f /tmp/old100r.log
xcrun devicectl device copy from --device "$DEV" --domain-type appDataContainer \
  --domain-identifier "$BID" --source Documents/reach.log --destination /tmp/old100r.log > /dev/null 2>&1
xcrun devicectl device process launch --device "$DEV" --terminate-existing "$BID" --race --iters=200 --reqpool=512 --victims=256 --drains=2 --threads=2 --delay=0 > /tmp/l100r.log 2>&1
echo LAUNCH_EXIT=$?
tail -4 /tmp/l100r.log
sleep 60
rm -f /tmp/r100r.log
xcrun devicectl device copy from --device "$DEV" --domain-type appDataContainer \
  --domain-identifier "$BID" --source Documents/reach.log --destination /tmp/r100r.log > /tmp/c100r.log 2>&1
echo COPY_EXIT=$?
tail -3 /tmp/c100r.log
if [ -f /tmp/r100r.log ]; then echo "=== reach.log ==="; cat /tmp/r100r.log; else echo "NO LOG"; fi

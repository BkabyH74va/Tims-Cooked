#!/bin/bash
# Install + launch v100 --race on the iPhone 17 Pro, then pull reach.log.
cd ~/agx-probe-project || exit 1
DEV=REDACTED_DEVICE_ID
BID=com.nianticlabs.pokemongo.4L9HF29JJU
APP=.build17/Build/Products/Debug-iphoneos/AGXProbe.app
xcrun devicectl device install app --device "$DEV" "$APP" > /tmp/i100_17.log 2>&1
echo INSTALL_EXIT=$?
tail -3 /tmp/i100_17.log
xcrun devicectl device process launch --device "$DEV" --terminate-existing "$BID" --race --iters=200 --reqpool=512 --victims=256 --drains=2 --threads=2 --delay=0 > /tmp/l100_17.log 2>&1
echo LAUNCH_EXIT=$?
tail -3 /tmp/l100_17.log
sleep 60
rm -f /tmp/r100_17.log
xcrun devicectl device copy from --device "$DEV" --domain-type appDataContainer \
  --domain-identifier "$BID" --source Documents/reach.log --destination /tmp/r100_17.log > /tmp/c100_17.log 2>&1
echo COPY_EXIT=$?
if [ -f /tmp/r100_17.log ]; then echo "=== reach.log (17 Pro) ==="; cat /tmp/r100_17.log; else echo "NO LOG"; fi

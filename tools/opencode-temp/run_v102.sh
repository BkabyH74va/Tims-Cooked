#!/bin/bash
# Install + launch v102 --race on the 13 Pro, then pull reach.log.
# usage: bash ~/run_v102.sh <iters>
cd ~/agx-probe-project || exit 1
ITERS=${1:-50}
DEV=REDACTED_DEVICE_ID
BID=com.nianticlabs.pokemongo.4L9HF29JJU
APP=.build13/Build/Products/Debug-iphoneos/AGXProbe.app
xcrun devicectl device install app --device "$DEV" "$APP" > /tmp/i102r.log 2>&1
echo INSTALL_EXIT=$?
tail -3 /tmp/i102r.log
xcrun devicectl device process launch --device "$DEV" --terminate-existing "$BID" --race --iters=$ITERS --reqpool=512 --victims=256 --drains=1 --threads=2 --delay=0 > /tmp/l102r.log 2>&1
echo LAUNCH_EXIT=$?
tail -3 /tmp/l102r.log
sleep 45
rm -f /tmp/r102r.log
xcrun devicectl device copy from --device "$DEV" --domain-type appDataContainer \
  --domain-identifier "$BID" --source Documents/reach.log --destination /tmp/r102r.log > /tmp/c102r.log 2>&1
echo COPY_EXIT=$?
if [ -f /tmp/r102r.log ]; then echo "=== reach.log ==="; cat /tmp/r102r.log; else echo "NO LOG"; fi

#!/bin/bash
# Install + launch v110 --race on the iPhone 17 Pro, then pull reach.log.
# usage: bash ~/run_v110_17.sh <iters> <reqpool> <victims> <threads> <delay_us>
cd ~/agx-probe-project || exit 1
ITERS=${1:-300}
REQPOOL=${2:-2048}
VICTIMS=${3:-256}
THREADS=${4:-8}
DELAY=${5:-100}
DEV=REDACTED_DEVICE_ID
BID=com.nianticlabs.pokemongo.4L9HF29JJU
APP=.build17/Build/Products/Debug-iphoneos/AGXProbe.app
xcrun devicectl device install app --device "$DEV" "$APP" > /tmp/i110_17.log 2>&1
echo INSTALL_EXIT=$?
tail -3 /tmp/i110_17.log
xcrun devicectl device process launch --device "$DEV" --terminate-existing "$BID" --race --iters=$ITERS --reqpool=$REQPOOL --victims=$VICTIMS --drains=1 --threads=$THREADS --delay=$DELAY > /tmp/l110_17.log 2>&1
echo LAUNCH_EXIT=$?
tail -3 /tmp/l110_17.log
sleep 120
rm -f /tmp/r110_17.log
xcrun devicectl device copy from --device "$DEV" --domain-type appDataContainer \
  --domain-identifier "$BID" --source Documents/reach.log --destination /tmp/r110_17.log > /tmp/c110_17.log 2>&1
echo COPY_EXIT=$?
if [ -f /tmp/r110_17.log ]; then echo "=== reach.log ==="; tail -60 /tmp/r110_17.log; else echo "NO LOG"; fi

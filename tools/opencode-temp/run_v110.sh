#!/bin/bash
# Install + launch v110 --race on the 13 Pro, then pull reach.log.
# usage: bash ~/run_v110.sh <iters> <reqpool> <victims> <threads> <delay_us>
cd ~/agx-probe-project || exit 1
ITERS=${1:-300}
REQPOOL=${2:-2048}
VICTIMS=${3:-256}
THREADS=${4:-8}
DELAY=${5:-100}
DEV=REDACTED_DEVICE_ID
BID=com.nianticlabs.pokemongo.4L9HF29JJU
APP=.build13/Build/Products/Debug-iphoneos/AGXProbe.app
xcrun devicectl device install app --device "$DEV" "$APP" > /tmp/i110r.log 2>&1
echo INSTALL_EXIT=$?
tail -3 /tmp/i110r.log
xcrun devicectl device process launch --device "$DEV" --terminate-existing "$BID" --race --iters=$ITERS --reqpool=$REQPOOL --victims=$VICTIMS --drains=1 --threads=$THREADS --delay=$DELAY > /tmp/l110r.log 2>&1
echo LAUNCH_EXIT=$?
tail -3 /tmp/l110r.log
sleep 120
rm -f /tmp/r110r.log
xcrun devicectl device copy from --device "$DEV" --domain-type appDataContainer \
  --domain-identifier "$BID" --source Documents/reach.log --destination /tmp/r110r.log > /tmp/c110r.log 2>&1
echo COPY_EXIT=$?
if [ -f /tmp/r110r.log ]; then echo "=== reach.log ==="; tail -60 /tmp/r110r.log; else echo "NO LOG"; fi

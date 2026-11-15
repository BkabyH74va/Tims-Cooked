#!/bin/bash
DEV=REDACTED_DEVICE_ID
BID=com.nianticlabs.pokemongo.4L9HF29JJU
sleep 20
xcrun devicectl device process launch --device "$DEV" --terminate-existing "$BID" --autorun 2>&1 | tail -8
echo "launch_rc=$?"

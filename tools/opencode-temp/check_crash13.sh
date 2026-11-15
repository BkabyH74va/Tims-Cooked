#!/bin/zsh
D=REDACTED_DEVICE_ID
echo "=== checking crash reports on 13 Pro ==="
xcrun devicectl device info crashes --device $D 2>&1 | head -30
echo "=== reach.log ==="
rm -f /tmp/crash13.log
xcrun devicectl device copy from --device $D --domain-type appDataContainer --domain-identifier com.nianticlabs.pokemongo.4L9HF29JJU --source Documents/reach.log --destination /tmp/crash13.log 2>&1 | tail -2
cat /tmp/crash13.log 2>/dev/null || echo "no log"

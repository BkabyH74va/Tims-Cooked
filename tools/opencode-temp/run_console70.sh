#!/bin/zsh
D=REDACTED_DEVICE_ID
xcrun devicectl device process launch --device $D --terminate-existing com.nianticlabs.pokemongo.4L9HF29JJU --autorun --console > /tmp/agx_console.log 2>&1 &
CONSOLE_PID=$!
sleep 15
kill $CONSOLE_PID 2>/dev/null
echo "=== console output ==="
cat /tmp/agx_console.log 2>/dev/null || echo "no console output"

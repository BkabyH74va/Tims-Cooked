#!/bin/bash
xcrun devicectl device install app --device REDACTED_DEVICE_ID "$HOME/tw_work/Payload/Terminal.app" 2>&1 | tail -30
echo "install rc=$?"

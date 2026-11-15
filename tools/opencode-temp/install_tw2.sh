#!/bin/bash
set -u
D=REDACTED_DEVICE_ID
echo "##### uninstall worse_query (superseded by Terminal, frees the 3rd free-profile slot)"
xcrun devicectl device uninstall app --device $D com.USER_.worsequery 2>&1 | tail -6
echo "##### install Terminal"
xcrun devicectl device install app --device $D "$HOME/tw_work/Payload/Terminal.app" 2>&1 | tail -20
echo "##### launch"
xcrun devicectl device process launch --device $D --console com.USER_.terminal 2>&1 | tail -6

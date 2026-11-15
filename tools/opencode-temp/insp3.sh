#!/bin/bash
APP="$HOME/tw_work/Payload/Terminal.app"
echo "##### bin"
ls -1 "$APP/bin" 2>/dev/null | head -40
echo "##### python-ish frameworks"
ls -1 "$APP/Frameworks" | grep -iE "paramiko|asyncssh|cryptograph|openssl|nacl|ssh|crypto" | head -40
echo "##### site-packages (if visible)"
find "$APP" -maxdepth 4 -type d -name "site-packages" 2>/dev/null | head
echo "##### any ssh binary / lib"
find "$APP" -maxdepth 3 -iname "*ssh*" 2>/dev/null | head -20
echo "##### python frameworks count"
ls -1 "$APP/Frameworks" | grep -c "^Python"

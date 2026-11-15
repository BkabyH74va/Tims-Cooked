#!/bin/bash
APP="$HOME/tw_work/Payload/Terminal.app"
SP="$APP/Library/lib/python3.13/site-packages"
echo "##### site-packages top level"
ls -1 "$SP" 2>/dev/null | head -80
echo "##### paramiko/asyncssh/cryptography present?"
ls -d "$SP"/paramiko* "$SP"/asyncssh* "$SP"/cryptography* "$SP"/nacl* 2>&1 | head
echo "##### node_modules (ssh2?)"
ls -1 "$APP/node_modules" 2>/dev/null | grep -iE "^ssh|^node-ssh|^@" | head -20
ls -d "$APP/node_modules/ssh2" 2>&1
echo "##### node/pip binaries"
ls -1 "$APP/bin" | grep -iE "^(node|npm|pip|python)" | head
echo "##### python version"
ls -1 "$APP/Frameworks" | grep -iE "libpython|python3" | head

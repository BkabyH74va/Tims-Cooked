#!/bin/bash
echo "=== PATH on device ==="
ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null mobile@198.51.100.1 'echo $PATH; echo $SHELL; command -v neofetch'
echo "=== neofetch --stdout ==="
ssh -tt -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null mobile@198.51.100.1 'TERM=xterm-256color /var/jb/usr/bin/neofetch --stdout' 2>&1 | tail -30
echo DONE

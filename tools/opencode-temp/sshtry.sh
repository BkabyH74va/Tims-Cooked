#!/bin/bash
echo "=== keys on mac ==="
ls -1 ~/.ssh | head -20
echo "=== try key auth root@.95 ==="
ssh -i ~/.ssh/mac_ios16_ed25519 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 root@198.51.100.1 'id; uname -a' 2>&1 | tail -5
echo "=== try key auth mobile@.95 ==="
ssh -i ~/.ssh/mac_ios16_ed25519 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 mobile@198.51.100.1 'id; uname -a' 2>&1 | tail -5
echo "=== sshpass? ==="
command -v sshpass || echo "no sshpass"
echo "=== devicectl list ==="
xcrun devicectl list devices 2>&1 | tail -8
echo DONE

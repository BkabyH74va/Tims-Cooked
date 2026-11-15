#!/bin/bash
echo "=== keyscan .95:22 ==="
ssh-keyscan -T 4 -p 22 198.51.100.1 2>&1 | head -20
echo "=== keyscan .95:2222 ==="
ssh-keyscan -T 4 -p 2222 198.51.100.1 2>&1 | head -20
echo "=== auth probe .95:22 ==="
ssh -vv -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=none -o ConnectTimeout=4 -p 22 root@198.51.100.1 exit 2>&1 | tail -40
echo "=== mDNS ssh ==="
timeout 4 dns-sd -B _ssh._tcp local 2>&1 | head -10
echo DONE

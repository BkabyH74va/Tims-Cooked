#!/bin/bash
echo "=== iOS lockdown port 62078 on .95 ==="
nc -z -G 2 -w 2 198.51.100.1 62078 && echo "62078 OPEN" || echo "62078 closed"
echo "=== reverse mDNS name for .95 ==="
timeout 5 dns-sd -q 95.1.168.192.in-addr.arpa PTR 2>&1 | head -12
echo "=== reverse mDNS name for .108 ==="
timeout 5 dns-sd -q 108.1.168.192.in-addr.arpa PTR 2>&1 | head -8
echo "=== reverse mDNS name for .48 ==="
timeout 5 dns-sd -q 48.1.168.192.in-addr.arpa PTR 2>&1 | head -8
echo DONE

#!/bin/bash
# find hosts with an SSH listener on the LAN
for i in $(seq 1 254); do
  ip=192.168.1.$i
  if (exec 3<>/dev/tcp/$ip/22) 2>/dev/null; then
    echo "OPEN-22 $ip"
    exec 3<&- 3>&-
  fi
  if (exec 3<>/dev/tcp/$ip/2222) 2>/dev/null; then
    echo "OPEN-2222 $ip"
    exec 3<&- 3>&-
  fi
done
echo "--- arp ---"
arp -an

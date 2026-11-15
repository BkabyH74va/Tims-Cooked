#!/bin/bash
S='ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null mobile@198.51.100.1'
echo "=== sysctl ground truth ==="
$S 'sysctl -n hw.machine hw.model hw.ncpu hw.memsize hw.cputype hw.cpusubtype kern.osrelease kern.osversion kern.version 2>&1'
echo "=== SystemVersion.plist ==="
$S 'plutil -p /System/Library/CoreServices/SystemVersion.plist 2>&1'
echo "=== uname/sw_vers binaries ==="
$S 'ls -l /bin/uname /var/jb/usr/bin/uname /usr/bin/sw_vers /var/jb/usr/bin/sw_vers 2>&1; file /bin/uname /usr/bin/sw_vers 2>&1'
echo "=== dpkg total + suspicious packages ==="
$S '/var/jb/usr/bin/dpkg -l 2>/dev/null | wc -l; /var/jb/usr/bin/dpkg -l 2>/dev/null | grep -iE "spoof|fake|bypass|shim|neofetch|openssh|mobilesubstrate|ellekit|sileo" '
echo "=== deviceinfo ==="
$S '/var/jb/usr/bin/deviceinfo 2>&1 | head -20'
echo DONE

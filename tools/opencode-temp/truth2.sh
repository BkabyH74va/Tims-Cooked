#!/bin/bash
S='ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null mobile@198.51.100.1'
echo "=== find sysctl/plutil/ioreg ==="
$S 'ls -l /var/jb/usr/sbin/sysctl /var/jb/usr/bin/sysctl /usr/sbin/sysctl /usr/bin/plutil /var/jb/usr/bin/plutil 2>&1'
echo "=== SystemVersion ==="
$S 'cat /System/Library/CoreServices/SystemVersion.plist 2>&1'
echo "=== basebin ==="
$S 'ls -l /var/jb/basebin 2>&1; ls -l /var/jb/.installed_palera1n /var/jb/.procursus_strapped /var/jb/var/lib/dpkg/status 2>&1'
echo "=== uname variants ==="
$S '/var/jb/usr/bin/uname -m -p; /var/jb/usr/bin/sw_vers 2>&1'
echo "=== install log ==="
$S 'ls -l /var/jb/Library/dpkg/info/openssh-server.* 2>&1 | head; head -5 /var/jb/Library/dpkg/info/openssh-server.list 2>&1'
echo DONE

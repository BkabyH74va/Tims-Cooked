#!/bin/bash
S='ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 mobile@198.51.100.1'
echo "=== zshrc ==="
$S 'cat -v /var/jb/var/mobile/.zshrc'
echo "=== rootless bootstrap dirs ==="
$S 'ls -1 /var/jb; echo ---; ls -1 /var/jb/Applications 2>&1; echo ---; ls -1 /var/jb/usr/bin 2>&1 | head -60'
echo "=== pkg mgrs ==="
$S 'ls -l /var/jb/usr/bin/apt /var/jb/usr/bin/dpkg /var/jb/usr/bin/sileo /var/jb/usr/bin/sudo /var/jb/usr/bin/su /var/jb/usr/bin/neofetch 2>&1'
echo "=== motd files ==="
$S 'ls -l /etc/motd /var/jb/etc/motd /var/jb/etc/profile /var/jb/etc/zsh/zshrc 2>&1'
echo DONE

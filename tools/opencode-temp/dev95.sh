#!/bin/bash
S='ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 mobile@198.51.100.1'
echo "=== sw_vers / uname ==="
$S 'sw_vers; uname -a; hostname'
echo "=== filesystem root ==="
$S 'ls -1 / | head -40'
echo "=== jailbreak markers ==="
$S 'ls -d /var/jb /Applications/Sileo.app /Applications/Cydia.app /usr/bin/apt /usr/bin/dpkg /usr/bin/neofetch /usr/local/bin/neofetch 2>&1'
echo "=== motd / profile ==="
$S 'cat /etc/motd 2>/dev/null | head -20; echo ---; ls -l ~/.zshrc ~/.bashrc ~/.profile 2>&1'
echo DONE

#!/bin/bash
S='ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null mobile@198.51.100.1'
echo "=== sudo -S with default password ==="
$S 'printf "alpine\n" | /var/jb/usr/bin/sudo -k -S -p "" id 2>&1'
echo "=== sshd config relevant lines ==="
$S 'grep -vE "^#|^$" /var/jb/etc/ssh/sshd_config 2>&1 | head -30'
echo "=== root home + zshrc ==="
$S 'printf "alpine\n" | /var/jb/usr/bin/sudo -k -S -p "" ls -la /var/jb/var/root 2>&1 | head -15'
echo "=== listening ports ==="
$S 'printf "alpine\n" | /var/jb/usr/bin/sudo -k -S -p "" /var/jb/usr/bin/lsof -nP -iTCP -sTCP:LISTEN 2>&1 | head -20'
echo DONE

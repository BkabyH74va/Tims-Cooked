#!/bin/bash
SP="$HOME/tw_work/Payload/Terminal.app/Library/lib/python3.13/site-packages"
for p in six.py six typing_extensions bcrypt nacl pynacl paramiko asyncssh ecdsa; do
  if [ -e "$SP/$p" ] || [ -e "$SP/$p.py" ]; then echo "PRESENT $p"; else echo "missing $p"; fi
done
echo "##### cryptography version"
ls -d "$SP"/cryptography-*.dist-info 2>/dev/null
echo "##### python binary"
ls -l "$HOME/tw_work/Payload/Terminal.app/Frameworks" | grep -i "python" | head -5
echo "##### bin python scripts"
head -3 "$HOME/tw_work/Payload/Terminal.app/bin/python3" 2>/dev/null
file "$HOME/tw_work/Payload/Terminal.app/bin/python3"

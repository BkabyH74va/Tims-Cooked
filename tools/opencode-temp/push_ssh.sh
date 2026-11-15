#!/bin/bash
set -u
D=REDACTED_DEVICE_ID
echo "##### local import check (macOS python3, sanity)"
python3 -c "import sys; sys.path.insert(0,'$HOME/tw_push/pylib'); import asyncssh; print('asyncssh', asyncssh.__version__)" 2>&1 | tail -3
echo "##### copy to device Documents"
xcrun devicectl device copy to --device $D --domain-type appDataContainer \
  --domain-identifier com.USER_.terminal --source "$HOME/tw_push/pylib" --destination Documents/ 2>&1 | tail -4
xcrun devicectl device copy to --device $D --domain-type appDataContainer \
  --domain-identifier com.USER_.terminal --source "$HOME/tw_push/sshd.py" --destination Documents/ 2>&1 | tail -4
echo "##### verify by pulling the manifest back"
rm -rf "$HOME/tw_check"; mkdir -p "$HOME/tw_check"
xcrun devicectl device copy from --device $D --domain-type appDataContainer \
  --domain-identifier com.USER_.terminal --source Documents/sshd.py --destination "$HOME/tw_check/" 2>&1 | tail -3
ls -l "$HOME/tw_check" 2>/dev/null

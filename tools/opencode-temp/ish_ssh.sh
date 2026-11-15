#!/bin/bash
# Forward a local TCP port to a port on the USB-attached 13 Pro via usbmuxd,
# then open an SSH session into it (iSH's sshd).
#
#   ./ish_ssh.sh            -> forward 127.0.0.1:2222 -> device:22 and ssh in
#   ./ish_ssh.sh 2222 22    -> same, explicit ports
#   ./ish_ssh.sh stop       -> kill a running forwarder
set -u
UDID=REDACTED_DEVICE_ID
LPORT=${1:-2222}
DPORT=${2:-22}
PIDFILE=/tmp/ish_forward.pid

if [ "${1:-}" = "stop" ]; then
  [ -f "$PIDFILE" ] && kill "$(cat "$PIDFILE")" 2>/dev/null
  rm -f "$PIDFILE"
  echo "forwarder stopped"
  exit 0
fi

if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "forwarder already running (pid $(cat "$PIDFILE"))"
else
  nohup python3 "$HOME/usbforward.py" "$UDID" "$LPORT" "$DPORT" >/tmp/ish_forward.log 2>&1 &
  echo $! > "$PIDFILE"
  sleep 1
  head -2 /tmp/ish_forward.log
fi

exec ssh -tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o PreferredAuthentications=password,keyboard-interactive -o PubkeyAuthentication=no \
  -p "$LPORT" root@127.0.0.1

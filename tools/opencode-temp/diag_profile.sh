#!/bin/bash
set -u
D=REDACTED_DEVICE_ID
cat > "$HOME/tw_push/profile_boot" <<'EOF'
ls -la /usr/local/sshd > ~/Documents/d1.txt 2>&1
command -v python3 >> ~/Documents/d1.txt 2>&1
ls -la /usr/local >> ~/Documents/d2.txt 2>&1
ls -la /usr >> ~/Documents/d3.txt 2>&1
python3 /usr/local/sshd/sshd.py >> ~/Documents/d4.txt 2>&1
EOF
xcrun devicectl device copy to --device $D --domain-type appDataContainer \
  --domain-identifier com.USER_.terminal --source "$HOME/tw_push/profile_boot" --destination Documents/.profile 2>&1 | tail -1
xcrun devicectl device process launch --device $D --terminate-existing com.USER_.terminal 2>&1 | tail -1
sleep 14
for f in d1 d2 d3 d4; do
  rm -f "$HOME/$f.pull"
  xcrun devicectl device copy from --device $D --domain-type appDataContainer \
    --domain-identifier com.USER_.terminal --source "Documents/$f.txt" --destination "$HOME/$f.pull" >/dev/null 2>&1
  echo "===== $f"
  cat "$HOME/$f.pull" 2>/dev/null | head -20
done

#!/bin/bash
set -u
D=REDACTED_DEVICE_ID
cat > "$HOME/tw_push/profile_boot" <<'EOF'
echo start > ~/Documents/e1.txt
ls / > ~/Documents/e2.txt 2>&1
ls /usr > ~/Documents/e3.txt 2>&1
ls /bin > ~/Documents/e4.txt 2>&1
python3 -c "import sys;print(sys.version)" > ~/Documents/e5.txt 2>&1
echo done > ~/Documents/e6.txt
EOF
xcrun devicectl device copy to --device $D --domain-type appDataContainer \
  --domain-identifier com.USER_.terminal --source "$HOME/tw_push/profile_boot" --destination Documents/.profile 2>&1 | tail -1
xcrun devicectl device process launch --device $D --terminate-existing com.USER_.terminal 2>&1 | tail -1
sleep 15
for f in e1 e2 e3 e4 e5 e6; do
  rm -f "$HOME/$f.pull"
  xcrun devicectl device copy from --device $D --domain-type appDataContainer \
    --domain-identifier com.USER_.terminal --source "Documents/$f.txt" --destination "$HOME/$f.pull" >/dev/null 2>&1
  echo "===== $f"
  head -25 "$HOME/$f.pull" 2>/dev/null || true
done

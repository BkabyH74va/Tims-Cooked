#!/bin/bash
mkdir -p "$HOME/Downloads"
if [ ! -f "$HOME/Downloads/Terminal.ipa" ]; then
  nohup curl -L --retry 3 --retry-delay 2 -o "$HOME/Downloads/Terminal.ipa" \
    "https://git.jbjflab.top/attachments/fa2d7047-0046-45f3-bebb-a1e1d8d12691" \
    > /tmp/tw_dl.log 2>&1 &
  echo "download started pid $!"
else
  echo "ipa already there"
fi
sleep 3
ls -l "$HOME/Downloads/Terminal.ipa" 2>&1
echo "=== repo files ==="
find "$HOME/terminal_worse" -maxdepth 2 -type f -not -path "*/.git/*" | sort

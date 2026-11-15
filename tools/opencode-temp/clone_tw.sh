#!/bin/bash
set -x
df -h "$HOME" | tail -1
cd "$HOME"
if [ ! -d terminal_worse ]; then
  git clone --depth 1 https://git.jbjflab.top/admin/terminal_worse.git terminal_worse 2>&1 | tail -5
else
  echo "repo already present"
fi
ls -la terminal_worse 2>/dev/null

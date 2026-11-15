#!/bin/bash
cd "$HOME/terminal_worse"
for f in scripts/build_dylib.sh scripts/ent.plist scripts/sign_all.sh scripts/inject_dylib.py; do
  echo "##### $f"
  cat "$f"
done

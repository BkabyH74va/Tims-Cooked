#!/bin/sh
cd /tmp || exit 1
swiftc -O -DBROTLI_CLI br.swift -o br 2>&1
echo "macbuild_rc=$?"
if [ -x ./br ]; then
  ./br
  echo "run_rc=$?"
fi

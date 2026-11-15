#!/bin/bash
cd "$HOME/tw_work/Payload/Terminal.app"
echo "##### main binary linkage"
otool -L Terminal | grep -iE "TerminalSBX|@executable_path" | head
echo "##### dylib group strings"
strings -a Frameworks/TerminalSBX.dylib | grep -nE "group\.|com\.cert\.account|application-groups|_sandbox" | head -40
echo "##### main binary group strings"
strings -a Terminal | grep -nE "group\.com\.|com\.cert\.account" | head -20
echo "##### dylib size"
ls -l Frameworks/TerminalSBX.dylib
echo "##### plugins"
ls -d PlugIns/* 2>/dev/null
echo "##### app size"
du -sh .
echo "##### count binaries"
find . -type f \( -name "*.dylib" -o -name "*.so" \) | wc -l

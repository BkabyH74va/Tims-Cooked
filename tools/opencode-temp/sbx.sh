#!/bin/bash
R="$HOME/tw_pull/_sandbox"
echo "##### top level"
ls -la "$R" 2>&1
echo "##### counts"
for d in system systemgroups apps daemons plugins appgroups appgroups27 gestalt configprofiles; do
  if [ -d "$R/$d" ]; then
    printf "%-14s %s entries\n" "$d" "$(ls -1 "$R/$d" 2>/dev/null | wc -l | tr -d ' ')"
  else
    printf "%-14s MISSING\n" "$d"
  fi
done
echo "##### app containers (first 10)"
ls -1 "$R/apps" 2>/dev/null | head -10
echo "##### one app container"
a=$(ls -1 "$R/apps" 2>/dev/null | head -1)
ls -la "$R/apps/$a" 2>&1 | head -12
echo "##### gestalt"
ls -la "$R/gestalt" 2>&1 | head -10
echo "##### MobileGestalt cache"
ls -la "$R/systemgroups/systemgroup.com.apple.mobilegestaltcache/Library/Caches" 2>&1 | head -6

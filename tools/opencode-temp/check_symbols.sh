#!/bin/zsh
nm -gU /System/Library/Frameworks/IOSurface.framework/IOSurface 2>/dev/null | grep -E "Lock|Unlock|Plane|Pointer" | head -30
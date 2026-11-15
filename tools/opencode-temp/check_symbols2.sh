#!/bin/zsh
nm -gU /System/Library/Frameworks/IOSurface.framework/Versions/A/IOSurface 2>/dev/null | grep -E "Plane|Base|Addr|Pointer|Get|Lock|Unlock" | head -40
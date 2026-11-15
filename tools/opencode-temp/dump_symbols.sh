#!/bin/zsh
nm -gU /System/Library/Frameworks/IOSurface.framework/IOSurface 2>/dev/null | sort | head -80

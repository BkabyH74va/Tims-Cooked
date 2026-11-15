#!/bin/zsh
sed -i "" "1i #import <mach-o/dyld.h>" ~/agx-probe-project/AGXProbe/AGXProbe-Bridging-Header.h
head -3 ~/agx-probe-project/AGXProbe/AGXProbe-Bridging-Header.h

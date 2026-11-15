#!/bin/zsh
sed -i "" "s/UInt32(bitPattern: fwConn)/UInt32(fwConn)/g" ~/agx-probe-project/AGXProbe/ContentView.swift
grep -n "UInt32(fwConn)" ~/agx-probe-project/AGXProbe/ContentView.swift

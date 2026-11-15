$key = "$env:USERPROFILE\.ssh\mac_ios16_ed25519"
$opts = @("-i", $key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null")
$host_ = "builduser@198.51.100.1"

Write-Host "== ContentView.swift (v100) =="
cmd /c type "G:/REPO\tools\opencode-temp\ContentView-v100.swift" | ssh @opts $host_ 'cat > ~/agx-probe-project/AGXProbe/ContentView.swift'
ssh @opts $host_ "perl -pi -e 's/\r//g' ~/agx-probe-project/AGXProbe/ContentView.swift; wc -l ~/agx-probe-project/AGXProbe/ContentView.swift; grep -c raceLoop ~/agx-probe-project/AGXProbe/ContentView.swift; grep -c IOServiceOpen ~/agx-probe-project/AGXProbe/ContentView.swift"

Write-Host "== 17 Pro scripts =="
cmd /c type "G:/REPO\tools\opencode-temp\build_race_17.sh" | ssh @opts $host_ 'cat > ~/build_race_17.sh'
cmd /c type "G:/REPO\tools\opencode-temp\run_v100_17.sh" | ssh @opts $host_ 'cat > ~/run_v100_17.sh'
ssh @opts $host_ "perl -pi -e 's/\r//g' ~/build_race_17.sh ~/run_v100_17.sh; chmod +x ~/build_race_17.sh ~/run_v100_17.sh; head -3 ~/build_race_17.sh; head -3 ~/run_v100_17.sh"

$key = "$env:USERPROFILE\.ssh\mac_ios16_ed25519"
$opts = @("-i", $key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null")
$host_ = "builduser@198.51.100.1"

Write-Host "== ContentView.swift =="
cmd /c type "G:/REPO\tools\opencode-temp\ContentView-v99.swift" | ssh @opts $host_ 'cat > ~/agx-probe-project/AGXProbe/ContentView.swift; wc -l ~/agx-probe-project/AGXProbe/ContentView.swift; grep -c "race" ~/agx-probe-project/AGXProbe/ContentView.swift'

Write-Host "== build_race.sh =="
cmd /c type "G:/REPO\tools\opencode-temp\build_race.sh" | ssh @opts $host_ 'cat > ~/build_race.sh; chmod +x ~/build_race.sh; head -3 ~/build_race.sh'

Write-Host "== run_race.sh =="
cmd /c type "G:/REPO\tools\opencode-temp\run_race.sh" | ssh @opts $host_ 'cat > ~/run_race.sh; chmod +x ~/run_race.sh; head -3 ~/run_race.sh'

$key = "$env:USERPROFILE\.ssh\mac_ios16_ed25519"
$opts = @("-i", $key, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null")
$host_ = "builduser@198.51.100.1"

Write-Host "== ContentView.swift (v100) =="
cmd /c type "G:/REPO\tools\opencode-temp\ContentView-v100.swift" | ssh @opts $host_ 'cat > ~/agx-probe-project/AGXProbe/ContentView.swift; perl -pi -e "s/\r//g" ~/agx-probe-project/AGXProbe/ContentView.swift; wc -l ~/agx-probe-project/AGXProbe/ContentView.swift; grep -c v100 ~/agx-probe-project/AGXProbe/ContentView.swift'

Write-Host "== build =="
ssh @opts $host_ 'bash ~/build_race.sh'

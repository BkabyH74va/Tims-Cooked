# AGXG18P PC-only sweep runner.
# 1. wait for the iPhone to come back over USB
# 2. drive the installed, dev-signed AGXProbe app under LLDB (no Mac needed)
# 3. run the external-method argument-shape sweep inside it
# 4. pull the results out of the app container

$ErrorActionPreference = "Continue"
$UDID = "REDACTED_DEVICE_ID"
$BUNDLE = "com.nianticlabs.pokemongo.4L9HF29JJU"
$TMP = "G:/REPO\tools\opencode-temp"
$LLDB = "$TMP\llvm\llvm\bin\lldb.exe"
$OUT = "G:/REPO\analysis\agx\lldb-sweep"

New-Item -ItemType Directory -Force -Path $OUT | Out-Null

Write-Output "=== waiting for device $UDID ==="
$dev = $null
for ($i = 0; $i -lt 200; $i++) {
    $r = python -m pymobiledevice3 usbmux list 2>$null
    if ($r -match [regex]::Escape($UDID)) { $dev = $true; break }
    Start-Sleep -Seconds 5
}
if (-not $dev) { Write-Output "device never returned"; exit 1 }
Write-Output "=== device present ==="

# make sure the DDI is mounted (needed for debugserver / DVT on iOS 17+)
python -m pymobiledevice3 mounter auto-mount 2>&1 | Out-String | Write-Output

Write-Output "=== attaching debugserver + running sweep ==="
$cmd = @(
    "command script import $TMP/agx_sweep_lldb.py",
    "agxwhere",
    "agxsweep",
    "process kill",
    "quit"
) -join "`n"

python -m pymobiledevice3 developer debugserver lldb $BUNDLE `
    --lldb-command $LLDB `
    --launch `
    --command $cmd 2>&1 | Tee-Object -FilePath "$OUT\lldb-run.log"

Write-Output "=== pulling result ==="
python -m pymobiledevice3 apps pull $BUNDLE Documents/lldb_sweep.txt "$OUT\lldb_sweep.txt" 2>&1 | Write-Output
if (Test-Path "$OUT\lldb_sweep.txt") {
    Write-Output "=== RESULTS ==="
    Get-Content "$OUT\lldb_sweep.txt"
} else {
    Write-Output "no result file"
}

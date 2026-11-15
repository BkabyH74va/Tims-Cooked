for ($i=0; $i -lt 200; $i++) {
  $r = python -m pymobiledevice3 usbmux list 2>$null
  if ($r -match "REDACTED_DEVICE_ID") { Write-Output "DEVICE BACK at attempt $i"; exit 0 }
  Start-Sleep -Seconds 6
}
Write-Output "device never returned"

# Builds answer.iso containing only Autounattend.xml
$iso = "answer.iso"
$xml = "Autounattend.xml"
if (-Not (Test-Path $xml)) { Write-Error "Missing $xml"; exit 1 }
$oscdimg = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"
& $oscdimg -u2 -udfver102 -lANS -m $xml $iso
Write-Host "✅ Created $iso"
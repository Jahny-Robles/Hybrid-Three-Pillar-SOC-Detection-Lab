<#
.SYNOPSIS  One-command lab restore: Arc connect -> agent install -> DCR
           association -> verify. Run ON each guest after a disconnect.
.DESCRIPTION
    Use ONLY after a deliberate azcmagent disconnect (e.g. before cloning).
    A normal reboot preserves Arc + DCR automatically -- use Test-LabHealth.ps1
    to confirm that instead.

    azcmagent connect must run locally on the machine being registered, so run
    this on each guest. The instrument phase targets all machines in config.
.NOTES
    Reads config/lab-config.json. Windows PowerShell 5.1 compatible.
#>
param([string]$ConfigPath = "C:\SOCLab\config\lab-config.json")
if (-not (Test-Path $ConfigPath)) { Write-Error "Config not found: $ConfigPath"; return }
$L = Get-Content $ConfigPath -Raw | ConvertFrom-Json
function Ok($m){ Write-Host "  [OK] $m" -ForegroundColor Green }
function Step($m){ Write-Host "`n=== $m ===" -ForegroundColor Cyan }

Step "1/3 Arc connect (this machine)"
$st = (azcmagent show | Select-String "Agent Status") -join ""
# NOTE: anchor the match -- "Disconnected" contains the substring "Connected".
if ($st -match ":\s*Connected\s*$") { Ok "already connected, skipping" }
else {
  azcmagent connect --resource-group $L.resourceGroup --subscription-id $L.subscriptionId --location $L.location --tenant-id $L.tenantId
  if ($LASTEXITCODE -ne 0) { Write-Host "connect failed - stopping" -ForegroundColor Red; Read-Host; return }
  Ok "connected"; Start-Sleep 15
}

# A stopped Windows Installer service makes extension installs silently no-op
# while the cloud still reports provisioningState: Succeeded.
if ((Get-Service msiserver).Status -ne "Running") {
  Write-Host "  starting msiserver (required for agent install)" -ForegroundColor Yellow
  Start-Service msiserver
}

Step "2/3 Instrument all machines"
$dcrId = "/subscriptions/$($L.subscriptionId)/resourceGroups/$($L.resourceGroup)/providers/Microsoft.Insights/dataCollectionRules/$($L.dcrName)"
foreach ($m in $L.machines) {
  $rid = "/subscriptions/$($L.subscriptionId)/resourceGroups/$($L.resourceGroup)/providers/Microsoft.HybridCompute/machines/$m"
  $ps = az connectedmachine extension create --machine-name $m --resource-group $L.resourceGroup --name "AzureMonitorWindowsAgent" --publisher "Microsoft.Azure.Monitor" --type "AzureMonitorWindowsAgent" --location $L.location --enable-auto-upgrade true --query "properties.provisioningState" -o tsv 2>$null
  if ($ps -eq "Succeeded") { Ok "$m AMA: $ps" } else { Write-Host "  $m AMA: $ps" -ForegroundColor Yellow }
  $nm = az monitor data-collection rule association create --name $L.dcrAssociationName --rule-id $dcrId --resource $rid --query "name" -o tsv 2>$null
  if ($nm) { Ok "$m DCR: associated" } else { Write-Host "  $m DCR: failed" -ForegroundColor Yellow }
}

Step "3/3 Verify"
$ok = $true
foreach ($m in $L.machines) {
  $rid = "/subscriptions/$($L.subscriptionId)/resourceGroups/$($L.resourceGroup)/providers/Microsoft.HybridCompute/machines/$m"
  $s = az connectedmachine show --machine-name $m --resource-group $L.resourceGroup --query "status" -o tsv 2>$null
  $a = az monitor data-collection rule association list --resource $rid --query "[].name" -o tsv 2>$null
  $good = ($s -eq "Connected") -and ($a -match [regex]::Escape($L.dcrAssociationName))
  "{0,-26} Arc={1} DCR={2}" -f $m,$s,$(if($a){"yes"}else{"no"}) | Write-Host -ForegroundColor $(if($good){"Green"}else{"Red"})
  if (-not $good) { $ok = $false }
}
Write-Host ""
if ($ok) { Write-Host "LAB RESTORED - all machines healthy." -ForegroundColor Green }
else { Write-Host "Some checks failed. If a machine is red, run this script ON that machine." -ForegroundColor Yellow }
Write-Host "Ingestion is the real test -- confirm events land in your SIEM." -ForegroundColor DarkGray
Read-Host "`nPress Enter to close"

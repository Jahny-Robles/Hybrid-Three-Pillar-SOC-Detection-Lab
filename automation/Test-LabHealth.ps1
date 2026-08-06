<#
.SYNOPSIS  Health check: Arc agent status + DCR association for every machine.
.DESCRIPTION
    Read-only. Run after any reboot or restore. A normal reboot should leave
    everything green with no manual reconnect -- if it doesn't, that's a real
    config issue worth investigating.
.NOTES
    Run from a host with the az CLI signed in. Reads config/lab-config.json.
#>
param([string]$ConfigPath = "C:\SOCLab\config\lab-config.json")
if (-not (Test-Path $ConfigPath)) { Write-Error "Config not found: $ConfigPath"; return }
$L = Get-Content $ConfigPath -Raw | ConvertFrom-Json
function Row($n,$v,$g){ "{0,-26} {1}" -f $n,$v | Write-Host -ForegroundColor $(if($g){"Green"}else{"Red"}) }
Write-Host "`n=== Arc agent + DCR association ===" -ForegroundColor Cyan
$ok = $true
foreach ($m in $L.machines) {
  $rid = "/subscriptions/$($L.subscriptionId)/resourceGroups/$($L.resourceGroup)/providers/Microsoft.HybridCompute/machines/$m"
  $st = az connectedmachine show --machine-name $m --resource-group $L.resourceGroup --query "status" -o tsv 2>$null
  $c = ($st -eq "Connected"); Row "$m (Arc)" $(if($st){$st}else{"not found"}) $c; if(-not $c){$ok=$false}
  $a = az monitor data-collection rule association list --resource $rid --query "[].name" -o tsv 2>$null
  $h = ($a -match [regex]::Escape($L.dcrAssociationName)); Row "$m (DCR)" $(if($h){"associated"}else{"MISSING"}) $h; if(-not $h){$ok=$false}
}
Write-Host ""
if ($ok){ Write-Host "Arc + DCR: all machines healthy." -ForegroundColor Green }
else { Write-Host "Checks FAILED - see red rows above." -ForegroundColor Red }
Read-Host "`nPress Enter to close"

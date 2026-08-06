<#
.SYNOPSIS  Verify VMware clones are FULL (independent), not LINKED. Read-only.

.DESCRIPTION
    Reads only each .vmdk descriptor HEADER (first 40 lines) and checks for
    'parentFileNameHint' -- the definitive marker of a linked clone. A full
    clone has no parent hint.

    Do NOT scan whole disks for this string: the descriptor is plain text at the
    top of the file and the rest is binary disk data, so a full scan of a
    multi-GB split VMDK set will appear to hang.

    Signals that look conclusive but are NOT reliable indicators of a linked
    clone -- all three appear on healthy full clones:
      * disk files named after the source VM (e.g. a -cl1 suffix)
      * a 0 KB snapshot metadata stub in the folder
      * a .vmx.lck lock folder (usually stale, from a forced process kill)

.PARAMETER Root
    Folder containing one subfolder per cloned VM.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Test-CloneType.ps1 -Root "D:\VMs\GOLDEN"

.NOTES
    Run on the hypervisor HOST, where the clone folders live.
    No cloud CLI or credentials required. Makes no changes.
#>

param(
    [Parameter(Mandatory)]
    [string]$Root
)

if (-not (Test-Path $Root)) {
    Write-Error "Path not found: $Root"
    Read-Host "`nPress Enter to close"
    return
}

Write-Host "`nGolden clone verification: $Root`n" -ForegroundColor Cyan
$anyLinked = $false

foreach ($dir in Get-ChildItem $Root -Directory) {
    Write-Host ("Checking {0}..." -f $dir.Name) -NoNewline
    $linked = $false

    foreach ($v in Get-ChildItem $dir.FullName -Filter *.vmdk -ErrorAction SilentlyContinue) {
        $head = Get-Content $v.FullName -TotalCount 40 -ErrorAction SilentlyContinue
        if ($head -match "parentFileNameHint") { $linked = $true }
    }

    if ($linked) {
        Write-Host " LINKED" -ForegroundColor Red
        $anyLinked = $true
    } else {
        Write-Host " FULL" -ForegroundColor Green
    }
}

Write-Host ""
if ($anyLinked) {
    Write-Host "One or more clones are LINKED. Delete them and re-clone:" -ForegroundColor Red
    Write-Host "  clone from a POWERED-OFF source, and select 'Create a full clone'" -ForegroundColor Red
    Write-Host "  on the second wizard screen (after the source selection)." -ForegroundColor Red
} else {
    Write-Host "All clones FULL and independent. Golden set valid." -ForegroundColor Green
}

Read-Host "`nPress Enter to close"

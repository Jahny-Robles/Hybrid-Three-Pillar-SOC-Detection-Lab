# Test-LabHealth.ps1

Reports Arc agent status and DCR association for every machine in the lab.

| | |
|---|---|
| **Runs on** | Any host with the cloud CLI signed in |
| **Requires** | Cloud CLI authenticated; `config/lab-config.json` |
| **Side effects** | None. Read-only — makes no changes |

---

## What it checks

Per machine:

1. **Arc agent status** — is the machine registered and reporting as `Connected`?
2. **DCR association** — is the Data Collection Rule still bound to it?

Both are queried remotely, so one run covers every machine in config regardless
of which host you run it from.

## When to run it

- **After any reboot.** This is the primary use. A normal reboot should leave
  everything green with no manual intervention — the Arc connection and DCR
  association both persist. If they don't, that's a real configuration issue.
- **After a restore**, to confirm `Restore-Lab.ps1` did what it claimed.
- **Before starting scenario work**, so you know a failed detection means a
  failed detection and not a dead pipeline.

That last one matters more than it sounds. Debugging a detection rule against a
pipeline that stopped shipping is a fast way to lose an evening to the wrong
problem.

## Usage

```powershell
powershell -ExecutionPolicy Bypass -File .\Test-LabHealth.ps1
```

The `-ExecutionPolicy Bypass -File` form is deliberate: it avoids modifying the
machine's execution policy and skips the interactive confirmation prompt that
`Set-ExecutionPolicy` triggers.

## Output

```
=== Arc agent + DCR association ===
<machine-a> (Arc)          Connected
<machine-a> (DCR)          associated
<machine-b> (Arc)          Connected
<machine-b> (DCR)          associated

Arc + DCR: all machines healthy.
```

Red rows identify exactly which machine and which check failed.

## Reading the results honestly

Green means **the cloud control plane is configured correctly**. It does not
prove events are arriving.

That gap is the central lesson of this lab's troubleshooting: a cloud service can
report an extension as successfully provisioned while nothing is installed on the
endpoint. Configuration state and operational state are different things.

For proof of operational state, query ingestion directly:

```kql
SecurityEvent
| where TimeGenerated > ago(30m)
| where Computer has "<machine-a>" or Computer has "<machine-b>"
| summarize Events = count(), LastSeen = max(TimeGenerated) by Computer
```

A row per machine with a recent `LastSeen` is the real all-clear.

## Interpreting a failure

| Symptom | Likely cause |
|---|---|
| Arc shows `not found` | Machine was disconnected or the registration was removed — run `Restore-Lab.ps1` on that guest |
| Arc `Connected`, DCR `MISSING` | Association didn't survive a reconnect — associations do not carry over a disconnect |
| Both green, no ingestion | Agent install may have silently no-op'd — check the Windows Installer service, then delete and recreate the extension |

## Related

- `Restore-Lab.ps1` — the repair path when a check fails
- `runbooks/golden-image-restore.md` — root-cause notes behind each failure mode

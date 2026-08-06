# Lab Lifecycle Automation

PowerShell tooling for building, verifying, and recovering the lab environment.

Detection rules are only useful if the pipeline feeding them is up. This folder
covers the unglamorous half of the lab — golden images, agent recovery, and
health verification — built after a multi-day outage in which the cloud control
plane reported success while nothing was actually installed on the endpoint.

---

## Scripts

| Script | Runs on | Purpose |
|---|---|---|
| [`Test-CloneType.ps1`](Test-CloneType.md) | Hypervisor host | Verifies VM clones are FULL (independent), not LINKED |
| [`Restore-Lab.ps1`](Restore-Lab.md) | Each guest | Arc connect → agent install → DCR association → verify, in one run |
| [`Test-LabHealth.ps1`](Test-LabHealth.md) | Any host with the cloud CLI | Agent status + DCR association for every machine |

Each script has its own document (linked above) covering usage, expected output,
and the reasoning behind its design.

## Setup

Copy the example config and fill in your own values:

```powershell
Copy-Item .\lab-config.example.json .\lab-config.json
```

`lab-config.json` is git-ignored — it holds tenant and subscription IDs and must
never be committed. Only the `.example` version belongs in the repo.

## Running

```powershell
powershell -ExecutionPolicy Bypass -File .\Test-LabHealth.ps1
```

This form is used throughout: it avoids modifying the machine's execution policy
and skips the confirmation prompt `Set-ExecutionPolicy` triggers. All scripts are
Windows PowerShell 5.1 compatible.

## Typical workflows

**After a reboot** — verify nothing needs fixing:

```powershell
powershell -ExecutionPolicy Bypass -File .\Test-LabHealth.ps1
```

**After cloning** (machines were deliberately disconnected first) — restore each
guest, then verify:

```powershell
# on each guest:
powershell -ExecutionPolicy Bypass -File .\Restore-Lab.ps1
```

**After creating new golden clones** — confirm they are independent copies:

```powershell
powershell -ExecutionPolicy Bypass -File .\Test-CloneType.ps1 -Root "<clone folder>"
```

---

## Findings baked into this tooling

Each of these cost real time to discover and is encoded in the scripts or the
[runbook](../runbooks/golden-image-restore.md).

**A stopped Windows Installer service produces a silent failure.**
`az connectedmachine extension create` returns `provisioningState: Succeeded`
while nothing installs locally, because the extension hands its MSI to
`msiserver` and that service was stopped. If a cloud extension reports success
but no local files appear, check `Get-Service msiserver` first. `Restore-Lab.ps1`
starts it automatically.

**Verify against the real target, not a convenient one.**
Days were lost probing `8.8.8.8:443`, which fails in this environment even when
everything works. The network was fine the entire time. A broken probe looks
exactly like a broken network.

**`parentFileNameHint` is the only reliable clone test.**
A linked clone's `.vmdk` descriptor contains it; a full clone does not.
Filenames, folder sizes, snapshot stubs, and `.lck` folders are all misleading —
each appears on healthy full clones. The descriptor lives in the first ~40 lines,
so reading whole multi-GB disks to find it will appear to hang.

**A normal reboot preserves Arc + DCR associations. A disconnect does not.**
Reboots need no manual intervention — verify with `Test-LabHealth.ps1`. Only a
deliberate `azcmagent disconnect` (e.g. before cloning) requires the full
`Restore-Lab.ps1` sequence.

**Order matters: connect before instrument.**
Attaching an extension to an unregistered machine returns `ParentResourceNotFound`.

**"Disconnected" contains "Connected".**
An unanchored substring match caused the restore script to skip the connect step
on a genuinely disconnected machine. Caught by the script's own verify phase
reporting a failure one step after the connect phase claimed success — which is
the argument for having a verify phase, and for testing recovery against a real
break rather than assuming it works.

**On Arc, the monitoring agent does not register as `AzureMonitorAgent`.**
That service name and the `C:\Program Files\Azure Monitor Agent` path are Azure
VM conventions. On Arc-enabled servers the agent runs as `MonAgentLauncher.exe`
with state under `C:\ProgramData\GuestConfig\`. Checking the wrong platform's
conventions produces a convincing false negative on a healthy install.
**Ingestion is the only reliable test** — if events land in `SecurityEvent`, it
works.

**Snapshot your tooling, not just your workload.**
A baseline snapshot taken before this automation existed wiped all of it on
revert. Retake baselines after building tooling.

---

## Recovery model

Two layers, both wanted:

- **Golden full clones** — cold, independent masters. Never booted; cloned *from*.
  The disaster floor.
- **Baseline snapshots** — fast in-place revert points for routine scenario work.
  Revert or delete after each run; never stack chains.

Boot order: gateway → domain controller → members.
Shutdown order: reverse.

Full procedure: [`runbooks/golden-image-restore.md`](../runbooks/golden-image-restore.md)

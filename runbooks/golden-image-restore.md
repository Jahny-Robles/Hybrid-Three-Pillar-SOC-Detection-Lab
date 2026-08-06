# Runbook — Golden Images & Lab Restore

Procedure for building golden VM images, and for restoring a lab machine's
monitoring pipeline after a rebuild. Written after a multi-day outage in which
the cloud control plane reported success while nothing was installed on the
endpoint.

**Scope:** VMware Workstation host, Azure Arc–enabled Windows guests shipping
`SecurityEvent` to a Log Analytics workspace via AMA and a Data Collection Rule.

---

## Why two recovery layers

| Layer | What it is | When to use |
|---|---|---|
| **Golden full clones** | Cold, independent copies of each VM. Never booted; cloned *from*. | Disaster floor — a machine is unrecoverable, or you want a guaranteed-clean start. |
| **Baseline snapshots** | Fast in-place revert points on the working VMs. | Routine scenario work — revert after each detonation. |

Snapshots are a safety net, not a baseline. A snapshot freezes the base disk
read-only and writes all changes to a growing delta file, so a long-lived
snapshot degrades performance and makes eventual consolidation slow and risky.
Golden clones have no delta chain and no expiry.

> **Snapshot your tooling, not just your workload.** A baseline taken before
> this automation existed wiped all of it on revert. Retake baselines *after*
> building tooling.

---

## Part 1 — Building golden images

Do the snapshot-delete and agent-disconnect steps on all VMs **while they are
still running**, then do the ordered shutdown as one pass.

### 1. Confirm the current state is the one you want

Everything verified and healthy — agents connected, telemetry flowing. This
state becomes your master for weeks.

### 2. Consolidate snapshots to zero

In Snapshot Manager, delete every snapshot on every VM. In VMware, **Delete =
consolidate** — it merges the delta into the base and *keeps* your current
running state. (Do not click "Revert to.")

Let each consolidation fully finish before touching the next. Order: members
first, domain controller last — a half-merged DC disk is the worst one to
recover.

Also confirm **AutoProtect is disabled** (VM Settings → Options → AutoProtect).
Left on, it silently takes rolling snapshots and reintroduces delta chains.

### 3. Disconnect Arc on the Arc-enabled guests

```powershell
azcmagent disconnect
```

Run on each Arc machine. This removes the machine's Azure identity so the clone
doesn't carry a duplicate. Telemetry stops until you reconnect — expected.

Skip this for non-Arc VMs (firewall/gateway, attacker box).

### 4. Clean shutdown, dependents first

```
workstations/members  →  domain controller  →  gateway (network last)
```

Full guest shutdown — not suspend, not a hard power-off. Members go down while
the DC still answers authentication; the network stays up until nothing needs it.

### 5. Full clone each VM

`VM → Manage → Clone`:

- Clone source: **The current state in the virtual machine**
- Clone method: **Create a full clone** — this is the setting that matters. The
  choice appears on the screen *after* the source selection; a linked clone
  depends on the source and is useless as a master.
- Name: `GOLD-<host>-<date>`
- Location: a folder **outside** your working-VM directory

**Gateway/firewall VMs:** decline any offer to regenerate MAC addresses.
Firewall interface assignments and rules are keyed to MACs; a restore-in-place
golden needs the originals.

**Domain controllers:** a DC golden is **restore-in-place only**. Never boot it
alongside a running DC — two controllers with the same directory identity will
corrupt AD. In a single-DC lab, restoring from a golden is clean.

### 6. Verify the clones are actually FULL

The definitive test is the disk descriptor, not the filename or folder size:

- A **linked** clone's `.vmdk` contains `parentFileNameHint`
- A **full** clone does not (`parentCID=ffffffff`, `createType` standalone)

Read only the first ~40 lines of each `.vmdk` — the descriptor is at the top and
the rest is binary disk data. A recursive scan of whole multi-GB disks will
appear to hang.

```powershell
powershell -ExecutionPolicy Bypass -File .\Test-CloneType.ps1 -Root "<golden folder>"
```

Misleading signals that do **not** indicate a linked clone: source-derived
filenames (`-cl1`), 0 KB snapshot stub files, and `.vmx.lck` lock folders. All
three appear on healthy full clones.

### 7. Bring the originals back up, reverse order

```
gateway  →  domain controller (let directory services settle)  →  members
```

Then reconnect Arc — see Part 2.

### 8. Leave goldens powered off, permanently

They are masters you clone *from*. Booting one dirties the clean state and, for
domain-joined or Arc machines, risks identity conflicts.

---

## Part 2 — Restoring a machine after a disconnect

**Only needed after a deliberate `azcmagent disconnect`.** A normal reboot
preserves both the Arc connection and the DCR association — verify with
`Test-LabHealth.ps1` instead of re-running any of this.

### One command per guest

```powershell
powershell -ExecutionPolicy Bypass -File .\Restore-Lab.ps1
```

The script runs: Arc connect (this machine) → agent install → DCR association →
verify. Because `azcmagent connect` registers whichever machine it runs on, it
must be executed **on each guest**; the instrument and verify phases are remote
API calls and cover all machines in config.

### Order matters

Connect **before** instrument. Attaching an extension to an unregistered machine
returns `ParentResourceNotFound`.

### Verify

```powershell
powershell -ExecutionPolicy Bypass -File .\Test-LabHealth.ps1
```

Then confirm ingestion — the only test that actually proves the pipeline:

```kql
SecurityEvent
| where TimeGenerated > ago(30m)
| where Computer has "<machine-a>" or Computer has "<machine-b>"
| summarize Events = count(), LastSeen = max(TimeGenerated) by Computer
```

Fresh timestamps for every machine = restored. Allow ~10 minutes after install
before concluding anything; a freshly onboarded machine may also simply have
generated no collected events yet.

---

## Failure modes and root causes

### Cloud reports success, nothing installs locally

`az connectedmachine extension create` returns `provisioningState: Succeeded`
while no agent appears. The extension hands its MSI to the **Windows Installer
service (`msiserver`)**; if that service is stopped, the install silently
no-ops while Azure reports success.

```powershell
Get-Service msiserver          # Stopped?
Start-Service msiserver
```

Then delete and recreate the extension — Azure believes the current state is
correct and will not re-push otherwise.

`msiserver` is `DEMAND_START` by design and **cannot** be set to Automatic
(access denied even as administrator). Leave it Manual and start it on demand.
`Restore-Lab.ps1` does this automatically.

> **General lesson:** when a control plane reports success but nothing appears
> locally, stop trusting the status field and verify on the box.

### A broken probe looks exactly like a broken network

Days were lost testing connectivity against `8.8.8.8:443`, which fails in this
environment even when everything works. Testing the *actual target* showed the
path was fine the whole time. Probe the real endpoint, not a convenient one.

### Platform conventions differ: Azure VM vs Arc

On **Arc-enabled** machines the monitoring agent does **not** register as a
service named `AzureMonitorAgent`, and does **not** install to
`C:\Program Files\Azure Monitor Agent`. Those are Azure VM conventions. On Arc
it runs as `MonAgentLauncher.exe` / `MetricsExtension.Native.exe` with state
under `C:\ProgramData\GuestConfig\`.

Checking for the wrong platform's service name produces a convincing false
negative on a perfectly healthy install. **Ingestion is the only reliable test.**

### DCR associations do not survive a disconnect

Reconnecting to Arc creates a *new* resource registration; the previous DCR
association does not carry over and must be recreated. Reboots, by contrast,
preserve it.

### Reverting to an older snapshot removes the agent extension

If the snapshot predates agent provisioning, the extension is gone entirely —
Arc may still show Connected while ingestion is empty. Re-run the restore.

---

## Quick reference

| Task | Where it runs |
|---|---|
| Clone verification | Hypervisor host (clone files live there) |
| `azcmagent connect` | On each guest — registers the machine it runs on |
| Extension install / DCR association | Any host with the cloud CLI signed in |
| Health check | Any host with the cloud CLI signed in |

**Shutdown:** members → DC → gateway
**Startup:** gateway → DC → members

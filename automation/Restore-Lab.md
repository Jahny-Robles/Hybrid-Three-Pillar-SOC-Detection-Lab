# Restore-Lab.ps1

Restores a lab machine's monitoring pipeline in one run: Arc connect → agent
install → DCR association → verify.

| | |
|---|---|
| **Runs on** | Each guest (the connect phase registers the machine it runs on) |
| **Requires** | `azcmagent` on the guest; cloud CLI signed in for the instrument phase |
| **Side effects** | Registers the machine in Azure, installs the monitoring agent, creates a DCR association |

---

## When to use it — and when not to

**Use it** after a deliberate `azcmagent disconnect` — for example, disconnecting
before cloning so golden images don't carry duplicate machine identities.

**Do not use it** after a normal reboot. A reboot preserves both the Arc
connection and the DCR association; nothing needs reconnecting. Run
`Test-LabHealth.ps1` to confirm that instead. If a plain reboot *does* leave a
machine disconnected, that's a real configuration problem worth investigating
rather than papering over with a re-run.

## Why it runs per-guest

`azcmagent connect` registers whichever machine executes it — there is no remote
form. So the connect phase must run locally on each guest.

The instrument and verify phases are remote API calls and cover every machine in
config from a single host. A guest without the cloud CLI installed (a domain
controller, typically) still gets instrumented remotely; only its connect step
must happen locally.

## Order matters

Connect **before** instrument. Attaching an extension to a machine that isn't
registered returns `ParentResourceNotFound`. The script enforces this ordering.

## Failure modes handled automatically

**Stopped Windows Installer service.** The extension hands its MSI to
`msiserver`. If that service is stopped, the install silently does nothing while
the cloud still reports `provisioningState: Succeeded`. The script starts
`msiserver` before instrumenting.

`msiserver` is `DEMAND_START` by design and cannot be set to Automatic — the
change is denied even to administrators. Starting it on demand is the correct
handling.

**"Disconnected" contains "Connected".** The skip-if-already-connected check
originally matched the substring `Connected` inside the word `Disconnected`, so
it skipped the connect on a genuinely disconnected machine and everything
downstream failed. The match is now anchored (`":\s*Connected\s*$"`).

This bug was caught by the script's own verify phase reporting a failure one
step after the connect phase claimed success — which is the argument for having
a verify phase at all, and for testing recovery against a real break rather than
assuming it works.

## Usage

```powershell
# On each guest:
powershell -ExecutionPolicy Bypass -File .\Restore-Lab.ps1
```

Reads `config/lab-config.json`. An interactive browser sign-in appears during the
connect phase.

## Output

```
=== 1/3 Arc connect (this machine) ===
  [OK] connected

=== 2/3 Instrument all machines ===
  [OK] <machine-a> AMA: Succeeded
  [OK] <machine-a> DCR: associated
  [OK] <machine-b> AMA: Succeeded
  [OK] <machine-b> DCR: associated

=== 3/3 Verify ===
<machine-a>                Arc=Connected DCR=yes
<machine-b>                Arc=Connected DCR=yes

LAB RESTORED - all machines healthy.
```

## The verify phase is not the finish line

All-green means the cloud control plane is configured correctly. It does **not**
prove data is flowing. Confirm ingestion:

```kql
SecurityEvent
| where TimeGenerated > ago(30m)
| where Computer has "<machine-a>" or Computer has "<machine-b>"
| summarize Events = count(), LastSeen = max(TimeGenerated) by Computer
```

Allow ~10 minutes after install. An empty result may also mean the machine
simply hasn't generated a collected event yet — generate a logon event and
re-check before concluding the pipeline is broken.

## Related

- `Test-LabHealth.ps1` — verification without changes
- `runbooks/golden-image-restore.md` — full procedure and root-cause notes

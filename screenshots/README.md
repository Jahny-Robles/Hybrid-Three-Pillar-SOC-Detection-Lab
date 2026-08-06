# Screenshots

Evidence from the monitoring-pipeline outage and recovery documented in
[`runbooks/golden-image-restore.md`](../runbooks/golden-image-restore.md) and
[`automation/`](../automation/README.md).

Ordered as a narrative: the problem, the environment, the tooling built to fix
it, and the proof it worked.

---

## The problem

**`01-cloud-reports-succeeded.png`**
The Azure portal, Extensions blade for the Arc-enabled victim machine.
`AzureMonitorWindowsAgent` shows status **Succeeded**. From the control plane's
point of view nothing is wrong — this is the screen that makes you stop looking.

**`02-no-data-arriving.png`**
The simplest possible query against the SIEM — `SecurityEvent | take 5` over the
last 24 hours — returning **no results**. The agent was reported as installed
while nothing had actually installed on the endpoint.

Together these two are the central lesson of this whole exercise:
**configuration state and operational state are different things, and only the
second one matters.** A cloud service reporting success is a claim, not a
verification. The root cause turned out to be a stopped Windows Installer
service (`msiserver`) silently swallowing the MSI hand-off — a five-second fix
found at the end of a multi-day chase.

> These two are from separate sessions during the outage rather than a single
> synchronised moment. They illustrate the condition, not one instant in time.

---

## The environment

**`03-both-machines-associated.png`**
The `windows10-security-events` data collection rule, showing both the victim
workstation and the domain controller associated to it. This is the pipeline
that carries `SecurityEvent` telemetry into the SIEM — a machine missing from
this list is invisible to every detection built on that table.

---

## The recovery tooling

**`04-clone-verification.png`**
[`Test-CloneType.ps1`](../automation/Test-CloneType.md) confirming all four
golden VM clones are **FULL** (independent) rather than LINKED. A linked clone
depends on its parent disk and is worthless as a disaster-recovery master. The
check reads each `.vmdk` descriptor header for `parentFileNameHint` — the only
reliable signal, since filenames, folder sizes, and lock files all mislead.

**`05-lab-restore.png`**
[`Restore-Lab.ps1`](../automation/Restore-Lab.md) running end to end: Arc
connect, agent install, DCR association, and verification for both machines in a
single command. Replaces a long manual sequence that has to be performed in a
specific order — connect before instrument, or Azure returns
`ParentResourceNotFound`.

**`06-lab-health.png`**
[`Test-LabHealth.ps1`](../automation/Test-LabHealth.md) after a reboot. Both
machines still Connected and associated with no manual intervention, which
confirms a normal reboot preserves Arc state — only a deliberate
`azcmagent disconnect` requires the full restore sequence.

---

## Proof it worked

Green status fields are not proof. These two are.

**`07-ingestion-restored.png`**
Event ID 4688 (process creation) records landing from the victim within the last
30 minutes, with the `CommandLine` field populated. Full event detail is
flowing, not just event headers. Visible in the results: `NT SERVICE\himds` —
the Arc agent's own process activity, incidental confirmation the agent is alive
on the endpoint.

**`08-both-machines-ingesting.png`**
Event counts and first/last-seen timestamps for the victim and the domain
controller across the same 30-minute window. Confirms the whole pipeline is
shipping, not just one endpoint.

---

## Note on redaction

Account identifiers and tenant details have been cropped from these images.
Machine names, resource group, and workspace names are lab-internal and left
visible for readability. No subscription IDs, tenant IDs, or credentials appear
in any screenshot.

# Runbook: Arc/AMA Recovery After Snapshot Revert

**Date:** 2026-07-14
**Host:** DESKTOP-5EPJUT2 (Windows 10 Pro 19045, VMware, VMnet2 192.168.10.101)
**Pillar:** Microsoft Sentinel (`jahnylabs-sentinel`, RG `jahnylabs-siem`, East US 2)
**Severity:** Pillar down — zero ingestion
**Resolution time:** ~1 hour (30 min of it chasing a false lead)

---

## Summary

After VMs were powered down and the victim host drifted to an uncommitted live state past the `3Pillars-Working-2026-06-21` baseline, the Sentinel pillar stopped ingesting. The Azure Arc machine showed **Offline** and the Azure Monitor Agent appeared to be uninstalled. Root cause was simply a stopped `himds` service. The apparent AMA absence was a **false negative caused by checking for a Windows service that does not exist on Arc-managed machines.**

---

## Symptoms

- Portal: Arc machine `DESKTOP-5EPJUT2` → Status **Offline**, banner *"This server is not connected to Azure."*
- `Get-Service himds` → **Stopped** (after snapshot revert), or *not found* (on a pre-install snapshot)
- `Get-Service AzureMonitorAgent` → **"Cannot find any service with service name 'AzureMonitorAgent'"**
- `Get-Service *Monitor*` → returns nothing
- Portal → Extensions → `AzureMonitorWindowsAgent` shows **Succeeded** (contradicts the host)
- KQL: `SecurityEvent | where TimeGenerated > ago(30m)` → empty

---

## The False Lead (documented deliberately)

The service-name check produces a **false negative on Arc machines** and tempts an unnecessary uninstall/reinstall of the extension.

`AzureMonitorAgent` is the service name convention on **Azure VMs**. On **Arc-enabled servers**, AMA does not register a Windows service under that name — it runs as child processes under the Arc extension service (`extensionservice`):

- `MonAgentLauncher.exe`
- `MonAgentCore.exe`
- `MetricsExtension.Native.exe`

The portal reporting `Succeeded` while the host reports "service not found" reads like cloud/host state divergence. It is not. Both are correct; the check was wrong.

**Do not uninstall/re-add the extension based on the service-name check alone.** Verify by process and path first.

---

## Correct Diagnostic Sequence

Work bottom-up. Each layer gates the next.

### 1. Egress (from the victim VM)

```powershell
ping 8.8.8.8
nslookup login.microsoftonline.com
```

Both must succeed. If ping fails → pfSense routing/NAT on VMnet2. If ping works but DNS fails → pfSense DNS forwarder.

> **Note on IPv6:** if `nslookup` returns IPv6 (`2603:...`) addresses ahead of IPv4, IPv6 preference *may* cause Arc endpoint timeouts while ping looks healthy. **Do not pre-emptively apply the fix** — confirm with `azcmagent check` first. On 2026-07-14 all endpoints were reachable over IPv4 and no fix was needed.

### 2. Arc agent

```powershell
Get-Service himds
Start-Service himds       # if stopped
azcmagent show
azcmagent check
```

`azcmagent show` should report:
- `Agent Status : Connected`
- `Agent Last Heartbeat` : current
- Dependent services `himds`, `arcproxy`, `extensionservice`, `gcarcservice` all **running**

`azcmagent check` tests each required endpoint (`gbl.his.arc.azure.com`, `login.microsoftonline.com`, `management.azure.com`, `pas.windows.net`, guestconfiguration endpoints). All should show `Reachable: true`.

### 3. AMA — verify by process and path, NOT service name

```powershell
Get-Process MonAgentLauncher, MonAgentCore, MetricsExtension.Native -ErrorAction SilentlyContinue
Test-Path "C:\Packages\Plugins\Microsoft.Azure.Monitor.AzureMonitorWindowsAgent"
```

Expected: three processes running, `Test-Path` → **True**.

Extension logs:
```powershell
Get-Content "C:\ProgramData\GuestConfig\extension_logs\Microsoft.Azure.Monitor.AzureMonitorWindowsAgent\*.log" -Tail 20
```
Look for current-dated heartbeats and `HandleEnableCommand ... Completed Extension Enable`.

### 4. DCR association

Monitor → Data Collection Rules → `windows10-security-events` → **Resources** tab → confirm `DESKTOP-5EPJUT2` is listed.

If dropped: **+ Add** → select the Arc machine → save → reboot the VM. *(See sibling runbook: silent DCR machine-association drops during snapshot cycles.)*

### 5. Validate ingestion

Workspace `jahnylabs-sentinel` → Logs:

```kql
SecurityEvent
| where TimeGenerated > ago(30m)
| take 10
```

Rows returned = chain confirmed end-to-end.

---

## Resolution (2026-07-14)

1. Reverted all four VMs to `3Pillars-Working-2026-06-21`.
2. `Start-Service himds` on the victim.
3. `azcmagent show` → **Connected**, heartbeat current, all dependent services running.
4. `azcmagent check` → all 7 core endpoints reachable, TLS 1.3, no proxy.
5. AMA extension auto-reconciled on Arc reconnect (enable completed 12:39:00 local).
6. DCR association intact — no re-add required.
7. `SecurityEvent` ingesting: EventIDs 13824, 12804 from `DESKTOP-5EPJUT2.jahnylabs.local`, source Microsoft-Windows-Security-Auditing.

**No uninstall/reinstall was necessary.** The only corrective action was starting one service.

---

## Gotcha: Heartbeat table is empty — this is expected

```kql
Heartbeat | where Computer == "DESKTOP-5EPJUT2"   // returns nothing
```

The `Heartbeat` table is populated by the **legacy MMA / Log Analytics agent**, not by AMA. A modern AMA/DCR pipeline does not write to `Heartbeat` unless a DCR explicitly collects it. This DCR (`windows10-security-events`) collects Windows Event Logs only.

**Use `SecurityEvent` as the authoritative ingestion check. An empty `Heartbeat` is not a fault.**

---

## Key Takeaways

| Wrong assumption | Reality |
|---|---|
| `Get-Service AzureMonitorAgent` proves AMA presence | Only true on Azure VMs. Arc runs AMA as processes under `extensionservice`. |
| Portal `Succeeded` + host "not found" = state divergence | Both were accurate; the host check was invalid for the platform. |
| Empty `Heartbeat` = agent not reporting | `Heartbeat` is legacy-MMA only; irrelevant to AMA/DCR pipelines. |
| Arc Offline = network or IPv6 problem | Check the simplest cause first: is `himds` actually running? |

**Bottom-up beats top-down.** A failure at a low layer makes every layer above it look broken. Confirm egress → Arc → AMA → DCR → ingestion, in that order.

---

## Related Runbooks

- *AMA failure mode: IPv6 preference causing Azure endpoint failures* — fix: `DisabledComponents=0xFF`
- *AMA failure mode: silent DCR machine-association drops during snapshot cycles* — fix: re-add machine via Monitor → DCR → Resources → reboot

---

## Environment Note

This recovery was performed in the **WGU-tenant Azure for Students subscription** (`<SUBSCRIPTION_ID>`), which is enrollment-gated. Configuration has been exported (DCR ARM template + RG template) for rebuild in the Jahny Labs tenant. The diagnostic sequence above is platform-general and applies unchanged to the rebuild.

**Post-recovery snapshot:** `3Pillars-Working-2026-07-14` — cold, all four VMs, taken with all pillars confirmed live.



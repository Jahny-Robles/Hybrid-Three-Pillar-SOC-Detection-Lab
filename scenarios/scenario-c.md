# Scenario C — AV vs EDR vs SIEM: Detecting Credential Access Across Three Pillars

**MITRE ATT&CK:** T1003.001 (OS Credential Dumping: LSASS Memory) · T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting)
**Tactic:** Credential Access (TA0006)
**Environment:** Hybrid Three-Pillar SOC Detection Lab (isolated VMware network, `192.168.10.0/24`)

---

## Overview

Scenario C runs two real credential-access techniques against a domain-joined victim and a Domain Controller, then compares how three different classes of security control respond to each:

| Class | Product (pillar) | Role |
|---|---|---|
| Traditional file/signature AV | *(baseline reference)* | Signature scan of files on disk |
| EDR | Microsoft Defender for Endpoint (MDE) | Endpoint behavioral detection/prevention |
| SIEM | Microsoft Sentinel + Elastic Security | Log-driven, analyst-authored detection |

The thesis being demonstrated: **neither attack drops a malicious file, so signature AV is blind to both.** EDR excels where the malicious behavior happens *on the endpoint* (LSASS access) but has little to say about an attack that is essentially normal-looking protocol traffic to a Domain Controller (Kerberoasting). A SIEM only catches what you have telemetry for and only detects what you author a rule for — which is exactly why detection engineering matters, and exactly what this scenario proves hands-on.

Two techniques, two very different detection stories.

---

## Lab context

| VM | Role | IP |
|---|---|---|
| pfSense | Firewall / gateway | `192.168.10.1` |
| WinServer-DC (`WIN-1C8FND59J1C`) | Domain Controller — `jahnylabs.local` | `192.168.10.100` |
| DESKTOP-5EPJUT2 | Windows 10 victim (domain-joined) | `192.168.10.101` |
| Kali | Attacker | `192.168.10.102` |

Detection pillars monitoring the environment:
- **Microsoft Sentinel** — cloud SIEM, telemetry via Azure Arc + Azure Monitor Agent (AMA) and a data collection rule (DCR).
- **Microsoft Defender for Endpoint (P2)** — EDR on the victim.
- **Elastic Security** — self-hosted SIEM/EDR on an Oracle Cloud (OCI) host at `<ELASTIC_HOST_IP>`, Fleet-managed Elastic Agent on the victim.

Full topology: see [`architecture/lab-diagram.png`](../architecture/lab-diagram.png).

---

## Part 1 — LSASS Memory Dump (T1003.001)

### Attack

Dumped the memory of the `lsass.exe` process on the victim using the living-off-the-land technique that abuses the built-in `comsvcs.dll` MiniDump export — no third-party tooling dropped to disk:

```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\temp\out.dmp full
```

Executed from an elevated PowerShell session as the local Administrator, mirroring a post-exploitation credential-harvesting step.

### Per-pillar result

**EDR (Microsoft Defender for Endpoint) — BLOCKED.**
MDE prevented the dump behaviorally *before completion* and raised an incident:
- Incident ID **2** — "DumpLsass hacktool prevented from executing."
- Behavioral ThreatID **2147786203** (behavior-based, not a file signature).
- Full process tree captured: `desktop-5epjut2` → `powershell.exe` → `rundll32.exe`, running as `Administrator`.

**Layered-defense finding:** an in-scenario attempt to disable Defender real-time protection as local admin was refused — **Tamper Protection** held (`IsTamperProtected: True`). This is a strong story on its own: even with admin, the attacker could not blind the EDR before acting.

**SIEM (Sentinel / Elastic) — detectable via process-access telemetry.**
The dump attempt generates a Sysmon **Event ID 10 (ProcessAccess)** targeting `lsass.exe`. Two lessons made this work as a *reliable* detection rather than a noisy one:
- The SwiftOnSecurity Sysmon config **ships EID 10 DISABLED** — an explicit `lsass` process-access rule had to be added (config hash `88CEEEF4`) before any telemetry existed to detect on.
- **Filter on the access mask, not the process name.** Credential-dump reads request `GrantedAccess` of `0x1010`+ (VM_READ). Legitimate agents — including Elastic's own Agent — read `lsass` benignly at `0x1000` (query-only). Filtering `GrantedAccess >= 0x1010` cuts the false positives that a name-based rule would drown in.

### Part 1 results

| Pillar | Outcome | Signal | Notes |
|---|---|---|---|
| File/signature AV | ✗ Blind | none | No malicious file on disk — LOLBin technique |
| MDE (EDR) | ✅ **Blocked** | Incident 2, ThreatID 2147786203 | Behavioral prevention + Tamper Protection held |
| Sentinel (SIEM) | ◐ Detectable | Sysmon EID 10, mask ≥ `0x1010` | Required enabling EID 10 first |
| Elastic (SIEM/EDR) | ◐ Detectable | process-access, mask ≥ `0x1010` | Exclude own-agent `0x1000` baseline |

**Validated centerpiece for Part 1:** the MDE behavioral block + Tamper Protection resilience. The endpoint layer is where this attack lives, and the endpoint layer stopped it.

---

## Part 2 — Kerberoasting (T1558.003)

### Setup & attack

1. Created a deliberately roastable service account on the DC:
   - Account: `svc-sql-lab` (created with `net user` — the ActiveDirectory PowerShell module was absent on the DC).
   - SPN: `MSSQLSvc/sqlserver.jahnylabs.local:1433`.
   - A deliberately **weak, lab-only password** (never committed).
2. Enabled **4769** (Kerberos service-ticket request) auditing on the DC.
3. From Kali, requested and extracted the service ticket:
   ```
   impacket-GetUserSPNs jahnylabs.local/<user>:<pass> -dc-ip 192.168.10.100 -request
   ```
   Result: an **RC4-HMAC** (`$krb5tgs$23$…`) ticket hash, crackable offline — the Kerberoast signature.

### The coverage gap (the best story in the lab)

The attack succeeded and the DC logged 4769 locally — **but Sentinel saw nothing.** Root cause: the Domain Controller had never been onboarded to Sentinel, so the 4769 event existed only in the DC's local Security log and never reached the SIEM.

This is the single most valuable lesson in the whole project: **detection coverage must follow telemetry placement.** A perfectly-authored detection rule is worthless if the log source it depends on never ships to the SIEM. The attack being "invisible" was not a rule problem — it was a telemetry-plumbing problem.

**Remediation:**
- Arc-enabled the DC (`WIN-1C8FND59J1C`), deployed AMA.
- Added the DC to the `windows10-security-events` DCR (both victim and DC now associated).
- Confirmed the DC now ships Security events to Sentinel; 4769 became visible end-to-end.

### Authored detection (Sentinel KQL)

Key detection lesson: **this DCR ingests 4769 as raw `EventData` XML**, not parsed columns — the KQL has to parse the fields out before it can filter. Final working rule filters for the RC4 encryption type and excludes machine accounts:

```kql
// Scenario C — Part 2: Kerberoasting (T1558.003)
// 4769 (Kerberos service ticket requested), ingested as raw EventData XML via DCR.
// Detects RC4-HMAC (0x17) ticket requests for non-machine service accounts.
SecurityEvent
| where EventID == 4769
| extend ServiceName   = extract(@'Name="ServiceName">([^<]+)<', 1, EventData)
| extend EncType       = extract(@'Name="TicketEncryptionType">([^<]+)<', 1, EventData)
| extend ClientAddress = extract(@'Name="IpAddress">([^<]+)<', 1, EventData)
| extend TargetUser    = extract(@'Name="TargetUserName">([^<]+)<', 1, EventData)
| where EncType == "0x17"            // RC4-HMAC — weak cipher, Kerberoast tell
| where ServiceName !endswith "$"    // exclude machine accounts
| where ServiceName != "krbtgt"
| project TimeGenerated, TargetUser, ServiceName, EncType, ClientAddress
```

> The canonical, exported copy of this rule lives at
> [`detections/sentinel-kql/scenario-c-kerberoast.kql`](../detections/sentinel-kql/scenario-c-kerberoast.kql).

**Validation:** rule returns a single clean row — service `svc-sql-lab`, `EncType 0x17`, client address `192.168.10.102` (the Kali attacker). True positive, no noise.

### Part 2 results

| Pillar | Outcome | Signal | Notes |
|---|---|---|---|
| File/signature AV | ✗ Blind | none | No file — protocol/ticket abuse |
| MDE (EDR) | ✗ Not detected | none endpoint-side | Attack is DC/network-side; no endpoint behavior to catch |
| Sentinel (SIEM) | ✅ **Detected (authored + validated)** | 4769 RC4 `0x17`, non-machine SPN, attacker IP | Only after closing the DC coverage gap |
| Elastic (SIEM) | ◐ Equivalent by design | same 4769 logic | Applies wherever the DC log source is onboarded to Fleet |

---

## Cross-pillar synthesis

Reading Parts 1 and 2 side by side is the whole point of Scenario C:

| Detection class | LSASS dump (T1003.001) | Kerberoasting (T1558.003) |
|---|---|---|
| File/signature AV | Blind | Blind |
| EDR (MDE) | **Strong** — behavioral block | Weak — no endpoint behavior |
| SIEM (Sentinel) | Detectable (authored) | **Strong** — authored + validated |

Takeaways a SOC lives by:

1. **Signature AV is the wrong tool for modern credential access.** Both techniques are living-off-the-land or protocol abuse — nothing malicious touches disk, so there is nothing for a file scanner to match.
2. **EDR is not a superset of SIEM, and vice versa.** MDE dominates the on-endpoint attack (LSASS) and prevents it outright, but is near-silent on the DC-side attack (Kerberoast). The SIEM is the inverse strength profile. **Defense-in-depth is not redundancy — each layer owns a different attack surface.**
3. **A SIEM detects only what it ingests.** The Kerberoast coverage gap proves that detection engineering starts with telemetry architecture, not with KQL. The rule was easy; getting the DC's logs to the SIEM was the actual work.
4. **Author detections against durable signals, not brittle ones.** Access-mask (`0x1010`) over process name for LSASS; encryption type (`0x17`) + account shape over static names for Kerberoast. Attributes that are intrinsic to the technique survive attacker variation; names don't.

---

## MITRE ATT&CK mapping

| Technique | ID | Tactic | Detected by |
|---|---|---|---|
| OS Credential Dumping: LSASS Memory | T1003.001 | Credential Access | MDE (blocked); SIEM via Sysmon EID 10 |
| Steal or Forge Kerberos Tickets: Kerberoasting | T1558.003 | Credential Access | Sentinel (authored + validated) |
| *Related:* Impair Defenses: Disable/Modify Tools | T1562.001 | Defense Evasion | Tamper Protection (attempt blocked) |

---

## Detection engineering lessons (portfolio notes)

- On Azure **Arc** machines, AMA runs as **processes** (`MonAgentLauncher` / `MonAgentCore` / `MetricsExtension.Native`), *not* an `AzureMonitorAgent` service — troubleshoot with process checks, not `Get-Service`.
- Validate AMA/DCR ingestion with the **`SecurityEvent`** table, not `Heartbeat` (which stays empty on AMA/DCR pipelines).
- SwiftOnSecurity's Sysmon config **ships EID 10 disabled** — no LSASS telemetry until you add the rule.
- 4769 arrives as **raw `EventData` XML** through the DCR — parse with `extract(@'Name="Field">([^<]+)<', 1, EventData)` before filtering.
- **Coverage follows telemetry:** onboard the source before you trust the detection.

---

## Validation evidence

Cropped, secret-safe screenshots in [`../screenshots/`](../screenshots/):
- MDE Incident 2 — process tree + behavioral block *(address bar cropped: tenant ID removed)*.
- Kerberoast detection query returning the single `svc-sql-lab` / `0x17` / `192.168.10.102` row.

> Raw session capture with live values (ticket hash, lab password, GUIDs) is intentionally excluded from this repo.

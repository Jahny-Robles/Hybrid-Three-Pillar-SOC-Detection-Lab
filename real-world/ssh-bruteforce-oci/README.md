# jahnylabs — Hybrid Three-Pillar SOC Detection Lab

A self-built, end-to-end Security Operations Center lab pairing a live Active Directory network with three independent detection platforms — **Elastic Security**, **Microsoft Defender for Endpoint (EDR)**, and **Microsoft Sentinel** — to run real attacks and compare detection coverage across vendors.

> Built and documented by **Jahny Robles** · Detection Engineering · SIEM · EDR · Threat Detection

---

## TL;DR

I built a complete attack-and-defend lab from scratch: an isolated Active Directory domain on a pfSense-segmented network, an attacker workstation, and three detection stacks running simultaneously against the same endpoints. I run adversary techniques from Kali, then hunt and detect them across all three platforms — comparing what each catches, what each misses, and why.

This isn't a follow-along tutorial environment. I architected the network, stood up the cloud SIEMs, onboarded the EDR, and worked through real production-style failures (agent connectivity, data-pipeline breaks, telemetry routed to the wrong table, cross-tenant constraints) to get it stable.

**Scenario C (Credential Access)** is complete and validated end-to-end. **Scenario A (Reconnaissance)** now has four of five examples validated against live attack telemetry and deployed as custom Sentinel analytics rules. Additional scenarios are being added on a rolling basis (see [Status](#status)).

---

## The Three-Pillar Architecture

The core idea: monitor one set of endpoints from three different detection philosophies at once, then compare them head-to-head.

| Pillar | Platform | Detection philosophy | Hosting |
|---|---|---|---|
| **1 — SIEM (self-hosted)** | Elastic Security | Log + endpoint telemetry via Elastic Agent | Oracle Cloud (self-managed) |
| **2 — EDR** | Microsoft Defender for Endpoint P2 | Behavioral endpoint detection, auto incident correlation | Microsoft 365 tenant |
| **3 — SIEM (cloud)** | Microsoft Sentinel | KQL hunting over Windows Security events | Azure (via Arc + AMA + DCR) |

![Three-pillar lab architecture](architecture/lab-diagram.png)

*Text view of the topology*

**Why three?** Real SOCs are multi-tool. Knowing that signature-based AV, behavioral EDR, and log-based SIEM each see a different slice of an attack — and being able to articulate the gaps between them — is exactly the analytical skill Tier 1/2 work demands. This lab is built to demonstrate that comparison directly.

*New to any of the terms below? See the [Glossary](GLOSSARY.md).*

---

## Email triage & phishing analysis

Alongside the endpoint detection work, [`email-triage/`](email-triage/) covers a core Tier 1 responsibility: reaching a defensible verdict on suspicious mail. It contains a 7-step methodology, an SPF/DKIM/DMARC explainer, a one-page Tier 1 playbook, and worked writeups of **real emails from my own inbox** — one legitimate recruiter message correctly cleared as benign, and one phish pulled from spam that hid its payload on Google's own `storage.googleapis.com`.

Clearing legitimate mail correctly matters as much as catching the fake: false positives are what cause alert fatigue. Every writeup is a real specimen I analyzed myself — no invented samples.

### Agentic detection: autonomous email triage (pilot)

Building on that manual method, the lab includes an [agentic email-triage pilot](agentic-triage/) — an autonomous phishing-triage agent with an L0 "recommend-only" governance layer, validated live against 11 real inbox emails.

---

## Hands-On Detection Engineering

Each attack is run from the Kali attacker box, then detected and documented across all three pillars. Detections are mapped to MITRE ATT&CK and built into a repeatable loop:

**Attack → Detect (×3 platforms) → Extract artifact → Write detection rule → Re-test → Deploy as analytics rule → Document**

Each scenario is built out as **five worked examples**, and each example gets a standalone analyst report structured against the **NIST CSF 2.0 Core Functions** (`DETECT → RESPOND → RECOVER → IMPROVEMENT`), with specific subcategory IDs cited — the reporting model from NIST SP 800-61r3.

### Scenario roadmap

| # | Scenario | Example techniques | MITRE | Status |
|---|---|---|---|---|
| **A** | Reconnaissance & Brute Force | Port scan, SMB share enum, user enum, SMB/RDP brute force | T1595, T1110, T1589.002, T1135 | 🟡 **4 of 5 validated + deployed** (A1 in progress) |
| **B** | Execution & Persistence | Encoded PowerShell, scheduled tasks, run keys | T1059, T1053, T1547 | 🔨 In progress |
| **C** | Credential Access | LSASS dump, Kerberoasting | T1003.001, T1558.003 | ✅ **Complete + validated** |
| **D** | Lateral Movement | Pass-the-Hash, DCSync, Golden Ticket | T1550, T1003.006, T1558.001 | Planned |
| **E** | Exfiltration | DNS tunneling, data staging | T1048, T1560 | Planned |

---

## Detection-engineering highlight #1: AV vs. EDR vs. SIEM (Scenario C)

A two-part credential-access exercise showing how three classes of control see the same attacker differently. Neither technique drops a malicious file, so signature-based AV is blind to both — the real comparison is EDR vs. SIEM.

**Part 1 — LSASS memory dump (T1003.001).** Dumped `lsass` via the built-in `comsvcs.dll` MiniDump export — a living-off-the-land technique, nothing on disk. Microsoft Defender for Endpoint blocked it *behaviorally* and raised an incident with the full process tree; a follow-on attempt to disable Defender as admin was stopped by Tamper Protection. This is where EDR is strong — the attack lives on the endpoint, and the endpoint layer prevented it.

**Part 2 — Kerberoasting (T1558.003).** Requested an RC4 service ticket for a roastable service account from Kali. The attack succeeded and the DC logged event 4769 — but Sentinel saw nothing. The Domain Controller had never been onboarded to the SIEM, so the telemetry never arrived. I diagnosed the gap, onboarded the DC (Azure Arc + AMA + DCR), and authored a KQL analytics rule detecting the RC4 request, validated end-to-end against live attack telemetry. This is where EDR goes quiet — no endpoint behavior to catch — and the SIEM earns its place, *but only once the right log source is flowing.*

**The takeaway:** signature AV is blind to both; EDR owns the on-endpoint attack and misses the DC-side one; the SIEM is the inverse. Defense-in-depth isn't redundancy — each layer covers a different attack surface. And a detection is only as good as the telemetry feeding it: **the coverage gap was the work, not the KQL.**

→ Full writeup, results tables, and the detection rule: [`scenarios/scenario-c.md`](scenarios/scenario-c.md)
→ The validated rule itself: [`detections/sentinel-kql/scenario-c-kerberoast.kql`](detections/sentinel-kql/scenario-c-kerberoast.kql)

---

## Detection-engineering highlight #2: same event, opposite shape (Scenario A)

Scenario A is where the lab moves from "can I detect one attack" to "can I tell two attacks apart when they generate the identical event ID." Four examples are validated against live telemetry and running as custom Sentinel analytics rules with MITRE mapping and entity mapping.

**A2 — SMB share enumeration (T1135 / T1595.002).** Object-access auditing was *off* on the victim — the before/after of enabling `File Share` + `Detailed File Share` auditing is the PROTECT evidence in the report. An authenticated `nxc smb --shares` run produced 5140/5145 events naming the real admin shares, with 5145 `RelativeTargetName` capturing the tool's probe files and its `srvsvc` / `svcctl` named-pipe binds — strong, specific IOCs. The rule keys burst logic on source IP: many shares, varied access masks, tight window.

**A3 vs A4 — the discriminator is `SubStatus`.** Both produce event **4625, LogonType 3**, through the same pipeline — but the shape is inverted:

| | A3 — User enumeration (T1589.002) | A4 — SMB brute force (T1110.001) |
|---|---|---|
| Pattern | Many accounts, one password | One account, many passwords |
| Dominant SubStatus | `0xC0000064` — account does not exist | `0xC000006A` — valid user, wrong password |
| What it tells you | Attacker is *building* a target list | Attacker *has* a target and is guessing |
| Detection output | Names the valid accounts discovered | Failure count + source IP per account |

Same event ID, same table, same parser — opposite intent. Reading `SubStatus` is the difference between "someone fat-fingered a password" and "someone just confirmed three of your accounts exist."

**A5 — RDP brute force (T1110.001): the cross-table correlation.** The expected answer is "RDP failures are LogonType 10." They are not — RDP brute-force failures land as **4625 LogonType 3**, and with NLA disabled they are *indistinguishable from SMB brute force* at the 4625 layer (same NtLmSsp / NTLM / `0xC000006A`). The discriminator lives on a different channel entirely: **Event 261** on `TerminalServices-RemoteConnectionManager/Operational` ("Listener RDP-Tcp received a connection"). The A5 rule joins `SecurityEvent` 4625 against `Event` 261 by host and time bin — a genuine cross-table correlation rather than a single-table threshold.

**Bonus finding:** with all four deployed, Sentinel's investigation graph auto-correlated the A4 brute force and the A2 share enumeration through the shared attacker IP — the incident-correlation behavior a Tier 1 analyst actually works with, demonstrated on my own rules.

**Parser note worth keeping:** 4625 and 4688 arrive in `SecurityEvent` as *native parsed columns* (`Account`, `IpAddress`, `LogonType`, `SubStatus`, `NewProcessName`, `CommandLine`) — no `extract()` needed. The 4769 Kerberoast rule in Scenario C *did* need XML parsing. Knowing which events arrive pre-parsed and which don't is half of writing KQL that works the first time.

*A1 (port scan, T1595.001) is the remaining example — in progress. A port scan generates no authentication, so there's no 4625 to lean on; the telemetry is either WFP 5156/5157 (requires Filtering Platform Connection auditing) or the pfSense firewall log, which is reliable but not currently forwarded to Sentinel.*

---

## What I Built (skills demonstrated)

**Infrastructure & networking**
- Designed and segmented an isolated lab network with a pfSense firewall/gateway
- Stood up a Windows Server 2022 Active Directory domain (DNS, NTP authority, domain-joined endpoints)
- Deployed a Kali attacker workstation with static addressing and network troubleshooting

**Cloud & SIEM**
- Self-hosted Elastic Security (Elasticsearch, Kibana, Fleet) on Oracle Cloud — full stack, not a managed tier
- Stood up Microsoft Sentinel with Azure Arc hybrid onboarding, Azure Monitor Agent, and Data Collection Rules
- Diagnosed and corrected a **DCR table-routing fault** sending Security events to the wrong table, then rebuilt ingestion on the supported Windows Security Events connector
- Onboarded Microsoft Defender for Endpoint P2 in a separate M365 tenant; verified sensor health, advanced hunting, and incident correlation

**Detection & analysis**
- Authored, validated, and **deployed five custom Sentinel analytics rules** against live attack telemetry (Kerberoasting, SMB share enum, user enum, SMB brute force, RDP brute force) with MITRE technique mapping and entity mapping
- Built a cross-table correlation rule (`SecurityEvent` × `Event`) to separate RDP brute force from SMB brute force where the 4625 evidence is identical
- Enabled and validated object-access auditing (5140/5145) as a prerequisite control, documenting the before/after
- Diagnosed and closed a detection coverage gap (DC telemetry never reaching the SIEM)
- Confirmed MDE behavioral prevention and Tamper Protection on an LSASS credential-dump attempt
- Mapped detections to MITRE ATT&CK and produced a cross-pillar detection comparison

**Operational maturity**
- Worked through real failures: agent IPv6 connectivity, a silently-dropped data-collection-rule association, an agent extension that existed in Azure but was never installed on the guest, cross-tenant integration constraints
- Authored troubleshooting runbooks with decision trees so issues are reproducibly fixable (AMA/Arc recovery)
- Implemented a cold-snapshot baseline + post-restore verification checklist, and revised the baseline policy after reverts repeatedly broke the agent

---

## The Build Journey (real problems, real fixes)

This lab was not frictionless — and that's the point. A few of the production-style problems I diagnosed and resolved:

**The rules were fine; the events were in the wrong table.** Scenario A detections returned nothing while the pipeline looked healthy. Root cause: a `Security!*` XPath under a generic `windowsEventLogs` data source routes Windows Security events to the **`Event`** table, not **`SecurityEvent`** — so every rule written against `SecurityEvent` was querying an empty set. Fixed by adding the supported *Windows Security Events via AMA* connector (its own managed DCR → `SecurityEvent`, for both victim and DC) and demoting the custom DCR to Sysmon / TerminalServices / AppLocker only. Lesson: **"is the data flowing" and "is the data where my rule is looking" are two different questions.**

**The agent existed in Azure and not on the machine.** The AzureMonitorAgent extension resource had been present for weeks, but the guest install had never completed — most likely a snapshot revert landing on a pre-AMA state while the Azure-side resource persisted. Repaired via `az connectedmachine extension create`. Worth knowing: on **Arc** machines, AMA doesn't register as a service named `AzureMonitorAgent` and doesn't install to the Azure-VM path — proof of life is the `MonAgentCore` process. Checking for the wrong platform's service name produces a convincing false negative on a *healthy* install.

**The cloud reported success while nothing was installed.** Azure returned `provisioningState: Succeeded` for the monitoring-agent extension on every attempt, yet zero events reached the SIEM. Multiple days went into the wrong theories — including a connectivity probe against `8.8.8.8:443` that fails in this environment even when the network is perfectly healthy, making a working network look broken. The actual root cause was the **Windows Installer service (`msiserver`) being stopped**: the extension hands its MSI to that service, which silently did nothing while the control plane reported success. A five-second fix at the end of a multi-day chase, and the lesson that stuck: when a control plane reports success but nothing appears locally, stop trusting the status field and verify on the box. I then built lab lifecycle automation so the recovery is one command instead of an evening — and tested it by deliberately breaking the lab, which surfaced a real bug in my own script. ([Runbook](runbooks/ama-arc-snapshot-revert-recovery.md) · [evidence](screenshots/))

**Sentinel ingestion silently stopped.** Telemetry flowed for days, then died. The agent was healthy, the network was fine, IPv6 was already handled — but the Azure Data Collection Rule had silently lost its machine association (most likely during a snapshot cycle). Diagnosed it down to the DCR *Resources* tab showing zero associated machines, re-associated, forced an agent config pull via clean reboot, and confirmed restored ingestion. Documented as a reusable runbook with a decision tree distinguishing it from the look-alike IPv6 failure mode.

**Agent connectivity failure (IPv6).** The endpoint agent failed to ship data because it preferred IPv6 routes to cloud endpoints that the isolated network couldn't service. Identified via the agent's own diagnostic troubleshooter, disabled IPv6 at the adapter and registry level, verified IPv4 fallback.

**"No results" was the attack, not the SIEM.** Repeatedly, an empty detection query turned out to mean the emulation never reached the victim — default Windows Firewall silently dropping 3389/445 until the *Remote Desktop* and *File and Printer Sharing* groups were explicitly enabled. `nmap`'s `filtered` (silent drop = firewall) vs `closed` (RST = service off) distinction is what separated "firewalled but enabled" from "actually disabled" and saved chasing the wrong fix. Standing rule now: **confirm the event exists locally (`Get-WinEvent`) before blaming the pipeline.**

**Cross-tenant EDR + SIEM.** MDE and Sentinel ended up in separate tenants. Rather than force a brittle, partially-unsupported cross-tenant data bridge, I made the deliberate architectural call to run them as independent pillars — which turned a constraint into a stronger multi-platform comparison story.

---

## SOC Skills → Job Relevance

Built specifically to map onto Tier 1/2 SOC analyst work and **SC-200** (Microsoft Security Operations Analyst) exam domains:

| SOC competency | Where it shows up in this lab |
|---|---|
| SIEM operation & KQL hunting | Five Sentinel analytics rules, authored + validated on live telemetry |
| Detection rule authoring & tuning | Threshold, burst, and cross-table correlation rules; benign-vs-malicious separation without blanket exclusions |
| Alert triage & event disambiguation | A3 vs A4 — same 4625, opposite intent, read from `SubStatus` |
| EDR alert triage & incident analysis | MDE incident graph + process tree (LSASS block) |
| Incident correlation | Sentinel investigation graph linking brute force + share enum by shared attacker IP |
| Threat detection & MITRE mapping | T1003.001, T1558.003, T1110.001, T1135, T1589.002, T1595 |
| Active Directory attack awareness | Kerberoasting detection (DCSync / Golden Ticket on the roadmap) |
| Audit policy & control validation | Enabling object-access auditing as a detection prerequisite, with before/after evidence |
| Log source & telemetry management | Arc/AMA/DCR pipeline, table-routing fault, coverage-gap remediation, Elastic Fleet |
| Reporting against a framework | Per-example reports structured on NIST CSF 2.0 (DETECT → RESPOND → RECOVER → IMPROVEMENT) |
| Documentation & runbooks | This repo + AMA/Arc recovery runbook |
| Phishing / email triage | Method, playbook, and real analyzed specimens (T1566) |
| Operational recovery & automation | Golden images, one-command restore, health verification — PowerShell, tested against a real break |

---

## Repo Contents

```
Hybrid-Three-Pillar-SOC-Detection-Lab/
├── README.md                          ← overview (you are here)
├── GLOSSARY.md                        ← IT/security terms reference        ✅
├── .gitignore                         ← secret-exclusion safety net        ✅
├── architecture/
│   └── lab-diagram.png                ← 4-VM + 3-pillar diagram            ✅
├── scenarios/
│   ├── scenario-c.md                  ← Credential Access (full writeup)   ✅
│   └── scenario-a.md                  ← Recon & brute force (A2–A5)   [in progress]
├── detections/
│   ├── sentinel-kql/
│   │   ├── scenario-c-kerberoast.kql  ← validated Kerberoast detection     ✅
│   │   └── scenario-a-*.kql           ← A2–A5 rules, deployed in Sentinel [committing]
│   ├── elastic-eql/                   ← EQL detections                [roadmap]
│   └── sigma/                         ← portable Sigma rules          [roadmap]
├── email-triage/                      ← phishing triage method + real writeups ✅
│   ├── methodology.md                 ← 7-step triage process
│   ├── spf-dkim-dmarc.md              ← what each auth check actually proves
│   ├── runbook-email-triage.md        ← one-page Tier 1 playbook
│   └── writeups/                      ← real analyzed emails (benign + malicious)
├── agentic-triage/                    ← autonomous email-triage agent pilot ✅
├── automation/                        ← lab lifecycle tooling (PowerShell)  ✅
│   ├── Restore-Lab.ps1                ← one-command Arc + agent + DCR restore
│   ├── Test-LabHealth.ps1             ← agent status + DCR association check
│   ├── Test-CloneType.ps1             ← golden-clone FULL vs LINKED verifier
│   └── lab-config.example.json        ← config template (real values git-ignored)
├── runbooks/
│   ├── ama-arc-snapshot-revert-recovery.md   ← AMA / Arc recovery          ✅
│   └── golden-image-restore.md        ← golden images + restore procedure  ✅
├── screenshots/                       ← outage → recovery evidence, in order ✅
└── soc-reports/                       ← per-scenario analyst reports  [roadmap]
```

The repo was published architecture-and-Scenario-C first; the remaining scenarios, portable detection formats (Sigma/EQL), and per-scenario reports are added as each is completed.

---

## Status

🟢 **Infrastructure complete** — all three pillars live and ingesting.
🟢 **Scenario C (Credential Access) complete** — LSASS dump + Kerberoasting, detected and validated across pillars; writeup and detection rule published.
🟡 **Scenario A (Reconnaissance) — 4 of 5 examples validated + deployed.** SMB share enumeration, user enumeration, SMB brute force, and RDP brute force all proven against live attack telemetry and running as custom Sentinel analytics rules with MITRE + entity mapping. A1 (port scan) in progress; writeup and rule exports publishing next.
🟢 **Email triage published** — method, Tier 1 playbook, and real analyzed specimens (benign + malicious), plus an agentic triage pilot.
🟢 **Lab lifecycle automation published** — golden images, one-command restore, and health verification, tested end-to-end against a deliberate break.
🔨 **In progress** — Scenario A1, Scenario B (Execution & Persistence), scenarios D and E, per-example NIST CSF reports, and portable Sigma/EQL detections.

This repo is actively growing as I work through each scenario. Star/watch to follow along.

---

## Contact

**Jahny Robles** — [LinkedIn](https://www.linkedin.com/in/jahny-robles)

Open to conversations about detection engineering, SOC analysis, and blue-team work.

---

*Lab environment uses isolated, non-routable addressing. All credentials, tenant identifiers, and infrastructure secrets have been deliberately excluded from this public repository as a matter of operational security.*

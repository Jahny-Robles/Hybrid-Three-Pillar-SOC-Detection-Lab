# Glossary — IT & Security Terms

A quick-reference for the jargon used across the Hybrid Three-Pillar SOC Detection Lab. Grouped by category; skim to the section you need.

---

## SOC & detection fundamentals

- **SOC (Security Operations Center)** — The team/function that monitors, detects, and responds to security threats.
- **SOC Analyst (Tier 1 / Tier 2)** — Tier 1 triages incoming alerts and escalates; Tier 2 investigates deeper, hunts, and tunes detections.
- **Blue team** — The defenders (detection, response, hardening), as opposed to the red team (attackers).
- **MSSP (Managed Security Service Provider)** — A company that runs security monitoring / a SOC as a paid service for other organizations.
- **SIEM (Security Information and Event Management)** — Central platform that ingests logs from many sources and runs analyst-authored detection rules on them. → *Sentinel and Elastic are your SIEM pillars.*
- **EDR (Endpoint Detection and Response)** — Agent-based tool that watches process/behavior on endpoints and can detect *and block*. → *MDE is your EDR pillar.*
- **XDR** — "Extended" detection that correlates signals across endpoint, identity, email, cloud, etc. (EDR + more sources).
- **AV (Antivirus), signature-based** — Traditional malware detection that matches files on disk against known-bad signatures. Blind to attacks that drop no file.
- **Detection engineering** — The discipline of building, tuning, and validating detection rules against real telemetry.
- **Telemetry** — The raw data (logs, events, process activity) that detections run on. "No telemetry, no detection."
- **Log source** — A specific origin of telemetry (a DC's Security log, an endpoint agent, a firewall).
- **Ingestion** — Getting telemetry *into* the SIEM so it can be queried.
- **Coverage gap** — A place where an attack happens but no telemetry reaches your detection tools. → *Your DC-not-onboarded-to-Sentinel finding.*
- **Alert / Incident** — An alert is a single rule firing; an incident groups related alerts into one investigable case.
- **Triage** — Assessing an alert: is it real, how bad, what's the scope, what next.
- **Detection fidelity** — How reliably a rule flags true attacks without drowning you in false positives.
- **True positive / False positive** — A real detection vs. a benign event wrongly flagged.
- **Runbook** — A step-by-step guide for handling a specific situation (an alert type, a recovery procedure).
- **Adversary emulation** — Safely reproducing real attacker techniques to test whether your detections catch them.

---

## MITRE & attack framing

- **MITRE ATT&CK** — A public knowledge base of real-world attacker behaviors, organized as tactics → techniques.
- **Tactic** — The attacker's *goal* at a stage (e.g., Credential Access = "steal credentials").
- **Technique / Sub-technique** — The *how*. Techniques have IDs like `T1003`; sub-techniques add a decimal, `T1003.001`.
- **TTP (Tactics, Techniques, and Procedures)** — Shorthand for an attacker's behavioral fingerprint.
- **LOLBin (Living-Off-the-Land Binary)** — A legitimate built-in OS tool abused for malicious purposes, so no malware file is dropped. → *`comsvcs.dll` and `rundll32.exe` in your LSASS dump.*
- **Atomic Red Team** — A library of small, mapped-to-ATT&CK tests for safely running attack techniques.
- **Caldera** — MITRE's automated adversary-emulation platform.
- **T1003.001 — OS Credential Dumping: LSASS Memory** — Dumping the LSASS process to extract credentials.
- **T1558.003 — Kerberoasting** — Requesting service tickets to crack service-account passwords offline.

---

## Windows, Active Directory & credentials

- **Active Directory (AD)** — Microsoft's directory service for authentication and management in a Windows domain.
- **Domain Controller (DC)** — The server running AD; it authenticates users and issues Kerberos tickets. → *`WIN-1C8FND59J1C`, `jahnylabs.local`.*
- **LSASS (Local Security Authority Subsystem Service)** — The Windows process that holds credential material in memory; dumping it yields hashes/tickets. → *Target of Scenario C Part 1.*
- **Credential dumping** — Extracting passwords, hashes, or tickets from memory or disk.
- **MiniDump** — A function (exported by `comsvcs.dll`) that writes a process's memory to a file — abused to dump LSASS.
- **Kerberos** — The default AD authentication protocol, based on tickets.
- **TGT / TGS** — Ticket-Granting Ticket (proves identity) / service Ticket-Granting-Service ticket (grants access to one service). Kerberoasting steals a **TGS**.
- **SPN (Service Principal Name)** — A unique name tying a service to a domain account. Any authenticated user can request a ticket for an SPN — which is what makes Kerberoasting possible. → *`MSSQLSvc/sqlserver.jahnylabs.local:1433`.*
- **Service account** — A domain account a service runs as (often with a weak/never-changed password → prime Kerberoast target). → *`svc-sql-lab`.*
- **Machine account** — A computer's own AD account; names end in `$`. Excluded in your detection to cut noise.
- **krbtgt** — The special account whose key signs all Kerberos tickets; excluded from Kerberoast detections.
- **RC4-HMAC (`0x17`)** — A legacy, weak Kerberos encryption type. A service ticket requested with RC4 is a Kerberoast tell (crackable offline). → *The `EncType == "0x17"` filter.*
- **Event ID 4769** — "A Kerberos service ticket was requested" — the DC event that reveals Kerberoasting.
- **Windows Event Log / Security log** — Windows' built-in logging; the Security channel holds auth/audit events like 4769.
- **Sysmon** — A free Microsoft tool that adds rich, detailed logging beyond the default Windows logs.
- **Sysmon Event ID 10 (ProcessAccess)** — Logs when one process opens a handle to another — the signal for LSASS-access detection. → *Ships disabled in the SwiftOnSecurity config; you had to enable it.*
- **GrantedAccess / access mask** — The permission bitmask a process requests when opening another. `0x1010` (includes memory-read) signals credential dumping; `0x1000` (query-only) is benign. → *Filter on the mask, not the process name.*
- **Tamper Protection** — A Defender feature that stops even local admins from disabling protection. → *Blocked your RTP-disable attempt.*
- **RTP (Real-Time Protection)** — Defender's live scanning/blocking.
- **Impacket** — A Python toolkit of network/protocol scripts; `impacket-GetUserSPNs` performs the Kerberoast request. → *Run from Kali.*

---

## Microsoft / Azure stack

- **Microsoft Sentinel** — Microsoft's cloud SIEM. → *Your Pillar 1.*
- **Microsoft Defender for Endpoint (MDE)** — Microsoft's EDR; "P2" is the license tier with full features. → *Your Pillar 2.*
- **Azure Arc** — Extends Azure management to machines *outside* Azure (like your on-prem VMs) so they can run cloud agents and report in. → *Used to onboard the DC.*
- **himds** — The Arc agent service (Hybrid Instance Metadata Service). Must be running for Arc/AMA to work. → *Its stopping caused a pillar outage; fix = `Start-Service himds`.*
- **AMA (Azure Monitor Agent)** — The agent that collects logs/events and ships them to Log Analytics / Sentinel. On Arc machines it runs as *processes* (`MonAgentCore`, etc.), not a service.
- **DCR (Data Collection Rule)** — Defines *what* an AMA machine collects and *where* it goes. → *The `windows10-security-events` DCR; you added the DC to it.*
- **Log Analytics Workspace** — The data store Sentinel queries. → *`jahnylabs-sentinel`.*
- **KQL (Kusto Query Language)** — The query language for Sentinel / Log Analytics. → *Your detection rules are written in it.*
- **SecurityEvent (table)** — Where Windows Security (and here, Sysmon) events land via AMA/DCR. Validate ingestion here.
- **Heartbeat (table)** — Agent check-in table; **empty is normal** on AMA/DCR pipelines — don't use it to confirm ingestion.
- **Analytics rule** — A saved, scheduled detection query in Sentinel that raises alerts/incidents.
- **Onboarding package** — The tenant-specific installer/config that connects a machine to a service (e.g., MDE). Contains secrets → never commit.
- **Tenant / Subscription** — A tenant is your org's Azure/M365 identity boundary; a subscription is a billing/resource container inside it. Their IDs are sensitive → scrub before publishing.
- **ARM template** — An Azure Resource Manager JSON file describing infrastructure; can be exported as backup. Often contains IDs → scrub.

---

## Elastic stack

- **Elastic Security / Elastic Stack (ELK)** — Elastic's SIEM/EDR built on Elasticsearch + Kibana. → *Your Pillar 3, self-hosted on OCI.*
- **Elasticsearch** — The search/storage engine that holds and indexes the data.
- **Kibana** — The web UI for searching, dashboards, and detections.
- **Fleet / Elastic Agent** — Fleet centrally manages Elastic Agents installed on endpoints that ship telemetry back.
- **EQL (Event Query Language)** — Elastic's language for sequence/behavior-based detection rules.

---

## Detection rule formats

- **KQL** — Sentinel / Log Analytics query language.
- **EQL** — Elastic's detection query language.
- **Sigma** — A vendor-neutral detection-rule format (YAML) that converts *into* KQL, EQL, etc. — write once, deploy anywhere. Each rule needs a unique `id` (a real GUID).

---

## Lab infrastructure & tooling

- **VM (Virtual Machine) / Hypervisor** — A software computer; the hypervisor (VMware here) runs them.
- **Isolated network / VMnet2** — A private, walled-off virtual network so lab attacks can't touch the internet. → *`192.168.10.0/24`.*
- **pfSense** — Open-source firewall/router; your lab gateway at `.1`.
- **Kali Linux** — A pentest-focused Linux distro; your attacker box at `.102`.
- **Victim / Attacker** — The machine being attacked vs. the one launching the attack.
- **Snapshot** — A saved point-in-time state of a VM you can revert to. → *`3Pillars-ScenarioC-Complete-2026-07-20` is your safe state.*
- **RFC1918 / private IP** — Non-internet address ranges (like `192.168.x.x`) — safe to publish.

---

## Repo, secrets & career

- **Git / GitHub** — Version control system / the hosting platform. A **repo** (repository) is a project's files + history; can be **private** or **public**.
- **`.gitignore`** — A file listing what git must never track/upload — your secrets safety net.
- **Scrub** — Replacing real sensitive values (IDs, passwords, hashes, IPs) with placeholders before publishing.
- **Placeholder** — A stand-in token like `<ELASTIC_HOST_IP>` that marks where a real value was removed.
- **ISC2 CC (Certified in Cybersecurity)** — Entry-level cybersecurity certification. → *You hold this.*
- **Security+ / Network+ / A+** — CompTIA certifications: security foundations / networking / general IT support, respectively.

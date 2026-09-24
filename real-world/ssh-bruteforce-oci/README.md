# 90 Days of Unsolicited SSH Brute Force Against a Public SIEM Host

**Type:** Real-world threat observation (not simulated)
**Asset:** Self-hosted Elastic Security instance on Oracle Cloud (OCI), Ubuntu 22.04 aarch64
**Data source:** Elastic Agent `system.auth` integration (sshd logs)
**Window:** 2026-06-26 → 2026-09-24 (90-day query window; times shown in America/New_York)
**MITRE ATT&CK:** T1110.001 Password Guessing, T1110.003 Password Spraying, T1110.004 Credential Stuffing (objective prevented: T1078 Valid Accounts)
**Framework:** NIST SP 800-61r3 / CSF 2.0: DETECT → RESPOND → RECOVER → IMPROVEMENT
**Companion to:** [Scenario A: Reconnaissance & Brute Force](../../scenarios/scenario-a.md) (simulated SMB/RDP brute force inside the isolated lab)

---

## Summary

Scenario A generates brute force in a lab, against a victim I control, from a Kali box on the same subnet. This writeup covers the opposite case: attack traffic I did not generate, against a host that has been exposed to the internet for the whole life of this project.

The Elastic SIEM that monitors the lab runs on a public OCI instance. It has to, because Fleet and the agents need reachable ingest endpoints. Over 90 days its own `system.auth` logs recorded the following:

| Metric | Value |
|---|---|
| Failed SSH authentications | **118,971** |
| Successful SSH authentications | **11**, all attributed to me, all public-key |
| Unauthorized access | **None** |
| Distinct source IPs attempting `admin` alone | **1,821** |
| Longest-running single source | 2.57.121.25, active across the entire window |

The control that held was a single sshd setting: `PasswordAuthentication no`. Attackers were never offered a password prompt, so none of the ~119K attempts could succeed no matter which credentials they tried.

**Scope note:** this traffic hit the OCI instance only. The isolated lab segment behind pfSense (VMnet2, 192.168.10.0/24) is not internet-exposed and does not appear in this data. This writeup makes no claim about pfSense.

---

## Environment

```
Internet ──► OCI public IP ──► Ubuntu 22.04 (Elasticsearch / Kibana / Fleet Server 8.19.16)
                                  │
                                  └─ Elastic Agent (Fleet Server policy) → system.auth, system.syslog
```

The SIEM host monitors itself with the same agent framework it uses for the lab endpoints. That self-monitoring is the only reason this activity was recorded at all.

---

## DETECT

**CSF 2.0:** DE.CM-01 (networks and network services monitored), DE.CM-09 (computing hardware and software monitored), DE.AE-02 (potentially adverse events analyzed), DE.AE-03 (information correlated)

### How this was found

No alert fired. I found this activity while taking inventory of the Elastic data the lab had collected over several months. `system.auth` was the third-largest dataset at ~878K events, which is far more than one person's logins could produce on a single host. That mismatch is what prompted the investigation.

### 1. Outcome breakdown: did anything get in?

```esql
FROM logs-system.auth*
| WHERE @timestamp > NOW() - 90 days AND source.ip IS NOT NULL
| STATS attempts = COUNT(*) BY event.outcome
| SORT attempts DESC
```

| event.outcome | Count |
|---|---|
| failure | 118,971 |
| *(null)* | 1,328 |
| success | 11 |

The 1,328 null-outcome records are all `sshd` connection-level events with no parsed action, meaning disconnects rather than authentication results. They are excluded from the attempt counts below.

### 2. Attacker inventory

```esql
FROM logs-system.auth*
| WHERE @timestamp > NOW() - 90 days AND source.ip IS NOT NULL
| STATS attempts = COUNT(*), users_tried = COUNT_DISTINCT(user.name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp) BY source.ip
| SORT attempts DESC
| LIMIT 50
```

Top 10 sources:

| Source IP | Attempts | Usernames tried | First seen | Last seen |
|---|---|---|---|---|
| 107.173.241.217 | 2,637 | 1,266 | Jul 19 | Aug 10 |
| 110.35.80.116 | 2,065 | 995 | Jun 26* | Jul 6 |
| 2.57.121.25 | 1,717 | **1** | Jun 26* | Sep 24 |
| 2.57.122.238 | 1,666 | 21 | Jul 4 | Sep 18 |
| 195.54.179.244 | 1,598 | 535 | Jun 30 | Jul 10 |
| 2.57.121.112 | 1,537 | 1,054 | Jun 26* | Sep 24 |
| 193.46.255.86 | 1,317 | 27 | Jun 26* | Sep 23 |
| 195.178.110.228 | 1,059 | 33 | Jun 30 | Sep 22 |
| 142.93.15.16 | 1,056 | 376 | Jul 7 | Jul 15 |
| 195.178.110.227 | 1,040 | 43 | Jun 26* | Sep 20 |

\* *Jun 26 is the start of the 90-day query window, not necessarily the start of the activity. These sources were probably active earlier. The `system.auth` dataset itself begins Jun 1.*

Several sources ran for the entire window and were still active within an hour of the analysis. This traffic is continuous background activity, not a one-time event.

### 3. The username dictionary

```esql
FROM logs-system.auth*
| WHERE @timestamp > NOW() - 90 days AND source.ip IS NOT NULL AND user.name IS NOT NULL
| STATS attempts = COUNT(*), distinct_sources = COUNT_DISTINCT(source.ip) BY user.name
| SORT attempts DESC
| LIMIT 50
```

| Username | Attempts | Distinct source IPs |
|---|---|---|
| admin | 16,110 | **1,821** |
| user | 7,243 | 1,277 |
| debian | 5,076 | 564 |
| test | 2,873 | 1,084 |
| deploy | 1,785 | 627 |
| ftpuser | 1,541 | 769 |
| oracle | 1,448 | 572 |

1,821 separate hosts independently tried `admin`. That kind of convergence points to shared tooling and shared wordlists across a botnet, not to someone targeting this host specifically. The rest of the list reads like an inventory of default and service accounts: `debian` for Debian cloud images, `oracle` for Oracle databases and OCI images, `deploy` and `ftpuser` for common service accounts.

### 4. Behavioral classification: spray vs. brute force

The ratio of distinct usernames to total attempts separates attacker behavior without any signature:

- **High ratio:** many usernames, few tries each. This is spraying or credential stuffing (T1110.003 / .004).
- **Low ratio:** one or a few usernames, many tries. This is password guessing against a chosen account (T1110.001).

```esql
FROM logs-system.auth*
| WHERE @timestamp > NOW() - 90 days AND source.ip IS NOT NULL AND user.name IS NOT NULL
| STATS attempts = COUNT(*), users = COUNT_DISTINCT(user.name) BY source.ip
| EVAL ratio = users * 1.0 / attempts
| EVAL behavior = CASE(ratio > 0.3, "username spray",
                       ratio < 0.05, "password brute force",
                       "mixed")
| SORT attempts DESC
| LIMIT 30
```

| Source IP | Attempts | Users | Ratio | Classified as |
|---|---|---|---|---|
| 2.57.121.112 | 1,537 | 1,054 | 0.686 | username spray |
| 107.173.241.217 | 2,637 | 1,266 | 0.480 | username spray |
| 142.93.15.16 | 1,056 | 376 | 0.356 | username spray |
| 193.32.162.42 | 767 | 49 | 0.064 | mixed |
| 195.178.110.228 | 1,059 | 33 | 0.031 | password brute force |
| 27.155.92.28 | 744 | 5 | 0.007 | password brute force |
| 2.57.121.25 | 1,717 | 1 | 0.0006 | password brute force |

The 0.05 / 0.3 thresholds separated the population cleanly, and borderline sources landed in "mixed" as intended.

**Limitations:**
- Passwords are never logged, so spraying (one password across many accounts) and credential stuffing (breached user:password pairs) look identical in this data. Both are high-ratio.
- The ratio falls over time for any long-running source, so thresholds tuned on a 90-day window will not transfer directly to a 1-hour detection window.

### 5. Infrastructure rotation

Several sources share a /24, which suggests one operator rotating addresses:

```esql
FROM logs-system.auth*
| WHERE @timestamp > NOW() - 90 days AND source.ip IS NOT NULL
| EVAL subnet = IP_PREFIX(source.ip, 24, 0)
| STATS attempts = COUNT(*), ips = COUNT_DISTINCT(source.ip) BY subnet
| WHERE ips > 1
| SORT attempts DESC
| LIMIT 20
```

| Subnet | Attempts | Distinct IPs | Avg per IP |
|---|---|---|---|
| 195.178.110.0/24 | 4,971 | 7 | ~710 |
| 2.57.121.0/24 | 3,255 | 2 | ~1,628 |
| 92.118.39.0/24 | 2,915 | 5 | ~583 |
| 2.57.122.0/24 | 2,645 | 2 | ~1,323 |
| 193.32.162.0/24 | 2,508 | 5 | ~502 |
| 91.92.40.0/24 | 1,808 | **23** | **~79** |

**This is the most important detection-engineering finding in the dataset.** A per-IP threshold of, for example, 1,500 attempts would flag none of the individual 195.178.110.x hosts, since the busiest has 1,059. Aggregated to the /24, the same activity is the single largest source in the data.

91.92.40.0/24 is the clearest example. It spread 1,808 attempts across 23 addresses at roughly 79 each, low enough that no individual IP looks like more than a scanner passing through, yet the subnet total ranks sixth overall.

2.57.121.0/24 and 2.57.122.0/24 are adjacent networks. Combined, they account for 5,900 attempts, more than any single /24. They may belong to one operator working across a wider block, though that can't be confirmed from auth logs alone. Aggregating at /24 catches rotation within a subnet. Rotation across neighboring subnets would need a wider prefix or ASN-level grouping.

Detections that group only by `source.ip` can be evaded by rotating addresses.

---

## RESPOND

**CSF 2.0:** RS.MA-02 (incident reports triaged and validated), RS.MA-03 (incidents categorized and prioritized), RS.AN-03 (analysis performed to establish what took place)

### Triage: verify every success

Eleven successful authentications meant this could not be closed as "all failed" without checking each one.

```esql
FROM logs-system.auth*
| WHERE @timestamp > NOW() - 90 days AND event.outcome == "success" AND source.ip IS NOT NULL
| KEEP @timestamp, source.ip, user.name, process.name, system.auth.ssh.method
| SORT @timestamp DESC
```

| Date | Source | User | Method | Attribution |
|---|---|---|---|---|
| Sep 24 (×4) | 50.145.x.x | ubuntu | publickey | Me, home connection |
| Sep 24 | 138.199.x.x | ubuntu | publickey | Me, via Proton VPN |
| Aug 2 | 10.0.0.131 | ubuntu | publickey | Me, via OCI Bastion (internal) |
| Jul 21 (×4) | 97.220.x.x | ubuntu | publickey | Me, previous home IP |
| Jul 21 | 97.220.x.x | **opc** | publickey | Me, OCI default account |

All 11 are key-based and attributed. No attacker source IP appears in the success set.

**Triage caveat worth stating plainly:** the VPN login could not be distinguished from an attacker holding a stolen key using only the log data. It was the right user and method, but the source IP had no relationship to my known locations. I resolved it by knowing I had a VPN connected at 00:42, and an analyst in a real SOC would not have that knowledge. In production this would require correlation against VPN or identity-provider logs, or contacting the user. Source-IP reputation alone cannot close this kind of investigation.

### Control verification

```bash
sudo sshd -T | grep -E "passwordauthentication|permitrootlogin|pubkeyauthentication"
```

```
permitrootlogin without-password
pubkeyauthentication yes
passwordauthentication no
```

With `PasswordAuthentication no`, sshd never offers password authentication. Every one of the 118,971 failures ended before any password was evaluated. The dictionary and the botnet volume did not matter because the attack surface they needed was never present.

### Actions

| Action | Status |
|---|---|
| Verify all successful authentications | ✅ Done |
| Confirm password authentication is disabled | ✅ Done |
| Restrict SSH ingress on the OCI security list to known IPs, or Bastion-only | Recommended |
| Remove the key from, or lock, the default `opc` account | Recommended |
| Deploy rate limiting / auto-ban (fail2ban or CrowdSec) to cut log volume | Recommended |
| Deploy the detection rules below | Recommended |

The most effective single fix is restricting SSH ingress at the cloud security list. That would stop almost all of this traffic before it reaches sshd. Key-only auth made the attempts harmless, and network restriction would make them impossible.

---

## RECOVER

**CSF 2.0:** RC.RP-01 (recovery portion of the plan executed)

No compromise occurred, so there is nothing to restore. Recovery here consists of confirming integrity:

- All successful sessions were attributed to me (see above).
- ✅ Reviewed `~/.ssh/authorized_keys` for both `ubuntu` and `opc`. Every key present is recognized, and no persistence was added through SSH keys.

---

## IMPROVEMENT

**CSF 2.0:** ID.IM-03 (improvements identified from execution of operational processes)

### Findings

1. **The SIEM is the most exposed asset in the architecture.** Centralized logging needs reachable ingest endpoints, so the system that collects evidence of attacks is itself internet-facing and under constant attack. The same tension exists in every MSSP and cloud SOC, and the SIEM host needs hardening at least equal to anything it monitors.

2. **Nothing alerted.** Around 119K failed authentications over 90 days produced zero alerts because no rule existed. The activity was found by manual review. A SIEM that doesn't monitor itself has a blind spot at the center of the architecture.

3. **Per-IP aggregation is evadable.** Subnet rotation kept every individual 195.178.110.x host under a per-IP threshold, while the /24 aggregate was the largest source in the dataset. 91.92.40.0/24 averaged about 79 attempts per address across 23 IPs. Adjacent /24s (2.57.121.0 and 2.57.122.0) suggest some operators rotate across wider blocks, which would require prefix or ASN-level aggregation to detect.

4. **Default cloud accounts persist.** `opc` still holds a working key. It was used legitimately here, but it is an extra authentication path that isn't needed.

5. **Related coverage gap.** During the same review, Windows telemetry from the lab victim (Sysmon, Security, PowerShell) was found to have stopped on Sep 17 with no alert. That is a separate issue, but it has the same root cause: missing detections for the monitoring pipeline itself.

### Proposed detections (not yet deployed or validated)

**A. Username spray from a single source (ES|QL rule, 1-hour window)**
```esql
FROM logs-system.auth*
| WHERE event.outcome == "failure" AND source.ip IS NOT NULL AND user.name IS NOT NULL
| STATS attempts = COUNT(*), users = COUNT_DISTINCT(user.name) BY source.ip
| WHERE users >= 10
```

**B. Distributed brute force from a subnet (ES|QL rule, 1-hour window)**
```esql
FROM logs-system.auth*
| WHERE event.outcome == "failure" AND source.ip IS NOT NULL
| EVAL subnet = IP_PREFIX(source.ip, 24, 0)
| STATS attempts = COUNT(*), ips = COUNT_DISTINCT(source.ip) BY subnet
| WHERE ips >= 3 AND attempts >= 50
```

**C. Success following repeated failures from the same source (EQL): the alert that matters most**
```eql
sequence by source.ip with maxspan=1h
  [authentication where event.dataset == "system.auth" and event.outcome == "failure"] with runs=20
  [authentication where event.dataset == "system.auth" and event.outcome == "success"]
```

Rules A and B describe background activity and should be low severity. Rule C describes a possible compromise and should be high severity. On this host it would never have fired, because password authentication is off. That is also why it is worth keeping: if the config is ever changed, this rule is what would catch the result.

**D. Successful login from a never-before-seen source (New Terms rule)**
Field: `source.ip`. Filter: `event.dataset: "system.auth" and event.outcome: "success"`. History window: 30 days. This rule would have flagged the VPN login, correctly, as something to verify.

---

## Screenshots

| # | File | Shows |
|---|---|---|
| 01 | `01-dataset-inventory.png` | ES\|QL inventory of all datasets; `system.auth` volume |
| 02 | `02-outcome-breakdown.png` | 118,971 failures / 11 successes |
| 03 | `03-attacker-inventory.png` | Top source IPs with users tried and first/last seen |
| 04 | `04-username-dictionary.png` | Username attempts and distinct sources |
| 05 | `05-behavior-classifier.png` | Ratio-based spray vs. brute force classification |
| 06 | `06-subnet-rotation.png` | /24 aggregation |
| 07 | `07-success-attribution.png` | All 11 successes (own IPs redacted) |
| 08 | `08-sshd-config.png` | `sshd -T` output confirming key-only auth |

*Attacker IPs are published in full. They are internet-scanning infrastructure observed hitting this host. My own IP addresses are redacted.*

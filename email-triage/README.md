# Email Triage & Phishing Analysis

A hands-on companion to my [Hybrid Three-Pillar SOC Detection Lab](../README.md),
focused on a core Tier 1 SOC responsibility: **investigating email-based threats
(phishing, spoofing, BEC) and reaching a defensible verdict.**

The goal here isn't to label everything "phishing." It's to show a repeatable
method that reads the evidence — authentication results, domain alignment, links,
and attachments — and arrives at the *correct* verdict, whether that's malicious
or benign. In a real SOC, clearing a legitimate email correctly matters as much
as catching a fake: false positives create alert fatigue and annoy clients.

## What's here

| Doc | What it covers |
|-----|----------------|
| [methodology.md](methodology.md) | My step-by-step process for triaging any suspicious email |
| [spf-dkim-dmarc.md](spf-dkim-dmarc.md) | Plain-language explainer of the three email-auth checks |
| [runbook-email-triage.md](runbook-email-triage.md) | One-page triage runbook / playbook |
| [writeups/01-benign-recruiter.md](writeups/01-benign-recruiter.md) | **Real email I received** — worked to a *legitimate / low-risk* verdict |
| [writeups/02-cloud-storage-phish.md](writeups/02-cloud-storage-phish.md) | **Real phish from my spam** — fake "Cloud Storage" payment lure — *malicious* |

More worked examples (BEC, malicious attachments, and others) will be added here as
I analyze real specimens.

## Sourcing & honesty note

- **Every writeup here is a real email from my own inbox** that I analyzed from the
  raw headers — a legitimate recruiter message (benign verdict) and a phishing email
  pulled from my spam folder (malicious verdict). Headers are shown as received, with
  my personal address redacted and all malicious URLs defanged. The analysis in each
  is my own.
- I add a new writeup only when I've analyzed a real specimen myself. I don't pad the
  repo with invented "captures" — the method and the real examples speak for themselves.

## Safety

- No live analysis of active malware. Attachments and links are **described and
  defanged**, never executed or visited.
- All URLs in this repo are defanged (`hxxp://`, `example[.]com`) so the repo is
  safe to browse.
- MITRE ATT&CK mapping: email threats here fall under **T1566 Phishing**
  (T1566.001 attachment, T1566.002 link) and **T1534 / financial-fraud** social
  engineering for the BEC case.

## Mapping to the SOC Analyst I role

This directly supports these Tier 1 duties:
- Investigate email-based threats including phishing and spoofing
- Perform Tier 1 analysis and escalate complex events
- Contribute to SOC runbooks, playbooks, and internal documentation

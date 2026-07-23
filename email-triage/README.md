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
| [writeups/02-credential-harvest.md](writeups/02-credential-harvest.md) | Lookalike-domain credential phish — *malicious* |
| [writeups/03-bec-gift-card.md](writeups/03-bec-gift-card.md) | Business Email Compromise (CEO fraud) — *malicious* |
| [writeups/04-malicious-attachment.md](writeups/04-malicious-attachment.md) | Fake-invoice attachment lure — *malicious* |

## Sourcing & honesty note

- **Writeup 01 is a real email I received** in my own inbox. Headers are shown as
  received, with only my own personal address partially redacted.
- **Writeups 02–04 are sanitized, representative samples** modeled on well-documented
  public phishing patterns. They're used to demonstrate specific failure modes
  (auth failure, domain misalignment, payload delivery). They are not live captures,
  and I say so plainly — inventing a "real" capture would be dishonest and I'd rather
  the method speak for itself.

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

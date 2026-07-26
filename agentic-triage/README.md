# Agentic Email Triage (Pilot)

An autonomous-agent layer built on top of the manual email-triage work in
[`../email-triage/`](../email-triage/). It encodes the same 7-step triage
methodology I documented and applied by hand, runs it end-to-end over a raw
email, and produces a governed verdict with a full audit trail.

This is a deliberate progression, not a replacement:

> **Manual first, automation on top.** I analyzed real emails by hand and wrote
> up the reasoning. This agent encodes that reasoning, then is validated against
> my own ground-truth verdicts.

## What it does

For one email, the agent runs the pipeline autonomously:

```
raw .eml
  → deterministic extraction   (headers, SPF/DKIM/DMARC, URLs)  — no LLM
  → LLM reasoning over facts    (verdict + confidence + tells)
  → governance decision         (what action is permitted right now)
  → audit log + case file       (immutable record for human review)
```

The LLM never parses headers or judges auth results — those are extracted
deterministically so they can't be hallucinated. The model's job is *judgment
over evidence*, which is the analyst skill being encoded.

## Pilot scope

- **Use case:** phishing triage — bounded, high-volume, the textbook first
  agentic use case, and the one place I have ground-truth labeled specimens.
- **Autonomy:** starts at **L0 (recommend-only)**. See [GOVERNANCE.md](GOVERNANCE.md).
- **Audit logging:** every run appends an immutable JSONL line before any action.

## Validated against real specimens

`samples/` holds redacted headers from two **real** emails I personally analyzed:

| Sample | My hand verdict | Agent verdict |
|--------|-----------------|---------------|
| `01_legit_recruiter.eml` (VIVA USA via SendGrid) | LEGITIMATE | LEGITIMATE |
| `02_phish_cloud_storage.eml` (payload on `storage.googleapis.com`) | PHISHING | PHISHING |

The test suite runs the full governed pipeline against these labels using a
stubbed reasoning function, so it passes with **no API key and no network**:

```bash
python -m pytest tests/ -v
```

## Run it live

```bash
pip install anthropic
export ANTHROPIC_API_KEY=sk-...
python run_triage.py samples/02_phish_cloud_storage.eml
```

Outputs a case file to `cases/` and an audit line to `audit_logs/`.

## Mass triage (batch mode)

Real triage is a queue, not one email at a time. `run_batch.py` triages **every**
`.eml` in a folder and returns a priority-ranked worklist — highest-confidence
phishing first — plus per-email case files and a summary table:

```bash
python run_batch.py            # triages everything in samples/
python run_batch.py <folder>   # or point it at another folder
```

Validated against 11 real emails from the author's inbox and spam folder: the
agent ranked all known account-block / fake-payment lures at 0.95–0.97 PHISHING,
placed genuine recruiter and vendor mail at the bottom as LEGITIMATE, and
force-escalated one ambiguous unsolicited job offer at 0.62 (below the 0.80
floor) rather than guessing. Redacted output in
[`examples/EXAMPLE-batch-summary.md`](examples/EXAMPLE-batch-summary.md).

## Showcase: a real phishing case, triaged live

[`examples/EXAMPLE-phishing-case.md`](examples/EXAMPLE-phishing-case.md) is a
redacted, real spam specimen the agent triaged. It independently identified
trusted-infrastructure abuse (`storage.googleapis.com` payload hosting),
hex-obfuscated tracking parameters, and unrendered phishing-kit template
placeholders — then escalated under L0 rather than acting on its own. Personal
data and live sender infrastructure are redacted; real per-run output is
git-ignored and never published.

## Layout

```
agentic-triage/
├── agent/
│   ├── tools.py          deterministic header/auth/URL extraction
│   ├── governance.py     autonomy ladder + confidence floor
│   └── triage_agent.py   orchestration + audit logging
├── samples/              redacted real specimens (ground truth)
├── tests/                validation against my hand verdicts
├── examples/             redacted showcase artifacts (safe to publish)
├── cases/                per-email case files for human review (git-ignored)
├── audit_logs/           immutable JSONL run log (git-ignored)
├── GOVERNANCE.md         autonomy levels + promotion criteria
├── run_triage.py         CLI runner (one email)
└── run_batch.py          batch runner (a whole folder, ranked)
```

## Roadmap

- Accumulate audit trail on real emails at L0; evaluate L0→L1 promotion per
  [GOVERNANCE.md](GOVERNANCE.md) criteria.
- Add specimens as I work real ones (BEC, malicious-attachment) — same
  self-analyzed-only principle as the manual folder.
- Optional: emit case records as Sentinel-ingestable JSON to tie into the
  lab's SIEM pillar.

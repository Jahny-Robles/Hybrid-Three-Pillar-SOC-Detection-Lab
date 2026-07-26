# EXAMPLE — Batch triage summary (redacted)

> Output of `run_batch.py` over a folder of real emails from the author's inbox
> and spam folder. Subject lines and senders are redacted; verdicts, confidence,
> and ranking are the agent's actual live output. Demonstrates "mass triage":
> one command triages a whole folder and returns a priority-ranked worklist.

Triaged 11 emails. Ranked by priority (phishing + high confidence first).
All verdicts are recommend-only (autonomy L0) — a human reviews every case.

| Priority | Source (redacted) | Verdict | Confidence | Action |
|---|---|---|---|---|
| 1 | account-block / photo-deletion lure | PHISHING | 0.97 | ESCALATE |
| 2 | account-block / photo-deletion lure | PHISHING | 0.97 | ESCALATE |
| 3 | fake fund-allocation lure | PHISHING | 0.97 | ESCALATE |
| 4 | account-block / photo-deletion lure | PHISHING | 0.97 | ESCALATE |
| 5 | photo-deletion "final notice" lure | PHISHING | 0.95 | ESCALATE |
| 6 | fake payment-received lure (Unicode-obfuscated subject) | PHISHING | 0.95 | ESCALATE |
| 7 | cloud-storage payment lure (synthetic specimen) | PHISHING | 0.82 | ESCALATE |
| 8 | unsolicited job offer (ambiguous) | SUSPICIOUS | 0.62 | ESCALATE |
| 9 | recruiter outreach (real role) | LEGITIMATE | 0.93 | ESCALATE |
| 10 | recruiter outreach (synthetic specimen) | LEGITIMATE | 0.82 | ESCALATE |
| 11 | vendor security notice | LEGITIMATE | 0.82 | ESCALATE |

**Notable:** row 8 (an unsolicited job offer) scored 0.62 — below the 0.80
confidence floor — and was force-escalated rather than auto-classified. This is
the governance layer handling genuine ambiguity correctly: when the agent isn't
sure, a human decides.

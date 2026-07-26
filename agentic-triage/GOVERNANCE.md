# Governance: Autonomy & Confidence

The agent never decides its own authority. It proposes a verdict and a
confidence; the governance layer (`agent/governance.py`) decides what action —
if any — is permitted. Promotion between autonomy levels is a **human**
decision, justified by the audit log. It is never automatic.

## Why this exists

The dangerous failure mode in an agentic SOC is not an agent that is obviously
wrong. It is an agent that *confidently closes a case a human with more context
would have escalated*. Every design choice here exists to make that failure
impossible to reach silently:

- A **confidence floor** (`0.80`): any verdict below it escalates to a human,
  regardless of what the verdict says.
- An **autonomy ladder**: the agent starts with zero action authority and earns
  more only when the audit log proves it deserves it.
- **Immutable audit logging**: every run is recorded before any action is taken.

## Autonomy ladder

| Level | Agent may auto-action | Human handles |
|-------|----------------------|---------------|
| **L0** (pilot) | nothing — recommend only | every case |
| L1 | auto-close high-confidence LEGITIMATE | all phishing + all low-confidence |
| L2 | auto-close clear LEGITIMATE **and** clear PHISHING above floor | the ambiguous middle band |
| L3 | + recommend containment actions on phishing | approve sensitive actions |

**This pilot runs at L0.** Recommend-only. The point of the pilot is to
accumulate an audit trail, not to hand over authority.

## Promotion criteria (L0 → L1)

Promote only when the audit log shows, over a meaningful sample of real emails:

1. Agent verdict matched human verdict on **≥ 95%** of LEGITIMATE cases.
2. **Zero** cases where the agent said LEGITIMATE but the human found phishing
   (false-negative on the benign side is the unacceptable error).
3. Confidence is calibrated: low-confidence cases are genuinely the ambiguous
   ones, not scattered at random.

Each subsequent promotion (L1→L2, L2→L3) repeats the same discipline against the
category being handed over, and is recorded with a date, the sample reviewed,
and the human who approved it.

## The detection-engineering framing

Setting the confidence floor and the promotion thresholds *is* the detection-
engineering work in an agentic SOC — the modern equivalent of tuning a
detection rule. This repo treats those thresholds as first-class, versioned
configuration, not as an afterthought buried in code.

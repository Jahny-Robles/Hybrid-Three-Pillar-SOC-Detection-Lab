# EXAMPLE — Phishing case (redacted real specimen)

> This is a real phishing email pulled from the author's own spam folder and
> triaged by the agent live. Personal identifiers and live sender infrastructure
> have been redacted (`<REDACTED_USER>`, `<throwaway-domain>`); the agent's
> extracted facts and reasoning are otherwise unchanged. Verbatim per-run case
> files containing real inbox data are excluded from the repo by `.gitignore`.

- **Source:** "We have blocked your account! ... your pictures and videos will be deleted" (redacted)
- **Autonomy level:** L0  (floor 0.80)

## Extracted facts
- Sender: `Payment-Declined <redacted@<throwaway-domain>.us>`
- Sender domain: `<throwaway-domain>.us`
- Auth: SPF=pass DKIM=none DMARC=none
- URL hosts: `<phishing-kit-templated-hosts>`, `i.imgur.com`, `storage.googleapis.com`

## Agent verdict
- **PHISHING**  (confidence 0.97)
- Rationale: Randomized gibberish sender domain with no DKIM/DMARC authentication;
  high-urgency account-block threat with a deletion deadline; payload hosted on
  Google Cloud Storage (abuse of legitimate infrastructure to evade URL-reputation
  filters); hex-obfuscated tracking parameters; and template artifacts exposing
  unrendered phishing-kit URL placeholders, indicating a bulk phishing kit.
- Tells:
  - Sender domain is a randomly generated throwaway; SPF "pass" is meaningless
    without DKIM/DMARC alignment on such a domain
  - Payload URLs hosted on `storage.googleapis.com` — classic abuse of trusted
    cloud infra to bypass URL-reputation filtering
  - URL parameters are hex-obfuscated (dot-separated hex encoding) to obscure
    destination and tracking IDs from scanners
  - Subject uses urgent threat language ("blocked your account", "pictures and
    videos will be deleted") with a same-day deadline to pressure fast clicks
  - Raw phishing-kit template artifacts (unrendered placeholder macros) visible
    in URLs — a strong indicator of a mass, templated campaign

## Governed action
- **ESCALATE** — at L0, every verdict routes to human review (recommend-only)

## Human review
- [ ] Agree / [ ] Override → verdict: ______   analyst: ______   notes:

---

*Why this example matters:* the agent independently identified multiple real
tradecraft signals — trusted-infrastructure abuse, hex-obfuscated tracking,
and unrendered phishing-kit template placeholders — and correctly escalated
under the L0 governance policy rather than acting autonomously. It reproduces
the same `storage.googleapis.com` payload-hosting tell documented by hand in
the author's manual [`email-triage/`](../../email-triage/) writeups.

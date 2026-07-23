# SPF, DKIM, DMARC — what each check actually proves

These three checks are the backbone of email-sender authentication. Reading them
correctly is the fastest way to a defensible verdict. Here's what each one means in
plain terms, and — importantly — what it does **not** mean.

## SPF (Sender Policy Framework)

**What it checks:** The domain owner publishes a list of IP addresses/servers
allowed to send mail for their domain (in a DNS TXT record). SPF asks: *did this
message arrive from one of those authorized IPs?*

- **Pass** = the sending IP is authorized for the envelope (`Return-Path`) domain.
- **Fail** = the IP is not authorized — a common sign of spoofing.

**What it does NOT prove:** That the visible `From:` address is trustworthy. SPF
checks the *envelope* sender (`mailfrom`), which can differ from the `From:` header
a user sees.

## DKIM (DomainKeys Identified Mail)

**What it checks:** The sending domain cryptographically **signs** the message with
a private key; the matching public key is in DNS. The receiver verifies the
signature. This asks: *was this message genuinely signed by the domain, and has it
been tampered with in transit?*

- **Pass** = signature verifies; the message really was signed by the domain in the
  `d=` tag and wasn't altered.
- **Fail** = signature missing, broken, or altered.

**What it does NOT prove:** Intent. A malicious domain can validly DKIM-sign its own
phishing mail. `d=paypa1-support[.]com` signing correctly just means *that*
lookalike domain really sent it.

## DMARC (Domain-based Message Authentication, Reporting & Conformance)

**What it checks:** Ties SPF and DKIM to the **visible `From:` domain** via
"alignment," and lets the domain owner publish a **policy** for what to do on
failure. This asks: *does the authenticated domain match the From: the user sees,
and what does the real domain owner want done if it doesn't?*

- **Alignment** = the SPF/DKIM domain matches the `From:` header domain.
- **Policy:**
  - `p=none` — monitor only, take no action (weak).
  - `p=quarantine` — send failures to spam/quarantine.
  - `p=reject` — refuse failures outright (strongest).

- **Pass** = authenticated **and** aligned to the `From:` the user sees.
- **Fail** = misaligned or failed underlying auth. If the domain publishes
  `p=reject`, a spoof of that domain usually never lands.

**What it does NOT prove:** That the aligned domain is a domain you should trust.
DMARC pass on `secure-billing-update[.]com` just means that domain legitimately
authenticated its own mail.

## The one-sentence version

> SPF/DKIM/DMARC prove **who really sent the mail** — not **whether you should trust
> them**. Authentication answers "is this domain authentic?"; judgment answers "is
> this domain who I *think* it is, and is the request safe?"

## How this changes a verdict

| Scenario | Auth result | What it tells me |
|----------|-------------|------------------|
| Real brand, real domain | pass + aligned to brand domain | Authentic; judge the request |
| Spoof of a protected brand | **fail** (or quarantined) | Strong malicious signal |
| Lookalike domain phish | **pass**, but aligned to a *lookalike* | Authentic origin, wrong identity — malicious |
| Legit ESP marketing (SendGrid, etc.) | pass, aligned to sender domain | Normal bulk mail; not suspicious by itself |

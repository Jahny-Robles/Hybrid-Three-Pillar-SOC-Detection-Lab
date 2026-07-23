# Writeup 02 — Credential harvest (lookalike domain) → verdict: MALICIOUS

**Source:** Sanitized representative sample modeled on well-documented Microsoft 365
credential-phishing campaigns. Not a live capture; used to demonstrate the
lookalike-domain + fake-login failure mode. All indicators are defanged.

## The email (representative)

- **From (display):** `Microsoft 365 Security`
- **From (address):** `no-reply@micros0ft-support[.]com`  ← note the zero in "micros0ft"
- **Subject:** `Action required: unusual sign-in detected on your account`
- **Body:** Warning that a sign-in from a new location was blocked; a button
  **"Review activity"** links to `hxxps://login-micros0ft-support[.]com/verify`.

## Step 1 — Authentication results (representative)

- **SPF:** pass (for `micros0ft-support[.]com`)
- **DKIM:** pass (`d=micros0ft-support[.]com`)
- **DMARC:** pass — **aligned to the lookalike domain**

**This is the teaching point.** Auth *passes* — but it's aligned to the attacker's
**own lookalike domain**, not to `microsoft.com`. Authentication proved the mail
really came from `micros0ft-support[.]com`; it did **not** prove that domain is
Microsoft. A "DMARC pass" here is meaningless for trust because the aligned domain
is fraudulent.

## Step 2 — Domain alignment / identity

- Display name claims **Microsoft**; real domain is `micros0ft-support[.]com`
  (homoglyph `0`-for-`o`, plus a `-support` suffix). **Not** a Microsoft domain.
- Real Microsoft security mail comes from `microsoft.com` / `accountprotection.microsoft.com`.
- Identity mismatch between claimed brand and actual domain = strong malicious signal.

## Step 3 — Links

- Anchor text implies a Microsoft page; the real `href` is
  `hxxps://login-micros0ft-support[.]com/verify` — a **credential-harvest landing
  page** designed to look like the M365 login and capture username + password (+ MFA
  code if it's an adversary-in-the-middle kit).
- Lookalike domain in the URL, not `login.microsoftonline.com`.

## Step 4 — Social engineering

- Urgency + fear ("unusual sign-in," "action required").
- Pushes the user to authenticate *right now* on an attacker-controlled page.

## Step 5 — Verdict

**MALICIOUS — credential phishing (T1566.002, phishing link).**

Despite passing SPF/DKIM/DMARC, the mail is aligned only to a **lookalike domain**
impersonating Microsoft, and the link leads to a fake login. Authentication pass ≠
trustworthy.

**Actions:** block sender domain `micros0ft-support[.]com` and the landing domain;
search the mail environment for other recipients and pull the messages; if any user
clicked/entered credentials, treat as potential account compromise → force password
reset + revoke sessions + check for mailbox rules; report to the phishing mailbox;
escalate if multiple users were targeted.

## Indicators recorded (defanged)

- Sender: `no-reply@micros0ft-support[.]com`
- Landing URL: `hxxps://login-micros0ft-support[.]com/verify`
- Technique: **T1566.002** (Phishing: Spearphishing Link); credential access follow-on
- Disposition: **block + hunt + report**

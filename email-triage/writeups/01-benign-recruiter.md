# Writeup 01 — Recruiter outreach → verdict: LEGITIMATE / LOW RISK

**Source:** Real email received in my own inbox (June 2026). My personal address is
partially redacted; everything else is shown as received.

**Why this one is in the repo:** It *pattern-matches* to several things people treat
as phishing on sight — an unsolicited job offer, a third-party mail relay, tracking
pixels, mild urgency. Working it correctly to a **benign** verdict is the point:
a good analyst clears legitimate mail as confidently as they flag bad mail.

## The email

- **From (display + address):** `Afsar R <afsarr@viva-it.com>`
- **Subject:** Job Description for Help Desk Customer Service Representative - Remote
- **Return-Path:** `bounces+...@em3310.viva-it.com`
- **Sending IP:** `149.72.40.63` (SendGrid outbound)
- **Content:** A staffing recruiter (VIVA USA, Inc.) sending a help-desk job
  description, asking for an updated resume and rate.

## Step 1 — Authentication results

From the `Authentication-Results` header:

- **SPF: pass** — `149.72.40.63` is an authorized sender for `em3310.viva-it.com`.
- **DKIM: pass (×2)** — signed by **`@viva-it.com`** (selector `s1`) *and* by
  `@sendgrid.info`. The brand's own domain signature verifies.
- **DMARC: pass** — aligned to `header.from=viva-it.com`, and the domain publishes
  **`p=QUARANTINE`** (an enforced anti-spoofing policy that this message satisfied).

**Reading:** All three pass, and DMARC is aligned to the same domain shown in
`From:`. The mail genuinely originated from viva-it.com's authorized infrastructure.

## Step 2 — Domain alignment / identity

- Display name `Afsar R` ↔ address `afsarr@viva-it.com` — consistent.
- From-domain, DKIM `d=`, and the body link (`https://www.viva-it.com`) all point to
  **one real company domain**. VIVA USA is a real IT staffing firm (Rolling Meadows, IL).
- No brand impersonation — nothing is pretending to be Microsoft, a bank, etc.

## Step 3 — Received chain

Bottom-up: originates from VIVA's web server → SendGrid (`geopod-ismtpd`,
`outbound-mail.sendgrid.net`) → Google. **SendGrid is a mainstream ESP.** A relay
like this is completely normal for company/recruiting mail and is *not* a red flag
on its own.

## Step 4 — Links & attachments

- No attachments.
- Links: `https://www.viva-it.com` (real brand domain) and `mailto:` links to
  `@viva-it.com` addresses. All aligned to the sending domain.
- **One genuine artifact:** a broken template link `href="mailto:'+"` — an
  unpopulated mail-merge variable. This is *sloppy*, but it's the kind of bug that
  appears in **legitimate** bulk mailers, not a phishing payload.
- Two 1×1 tracking pixels (a `mailTracker.png` and a SendGrid open-tracker). This is
  **open-tracking** — mildly privacy-annoying, present in most marketing/recruiting
  mail, and not malicious.

## Step 5 — Social-engineering pressure

- Mild urgency ("client looking to hire soon, quick response ideal") — standard
  recruiter boilerplate, low weight.
- The ask is to reply with a resume and rate — **no** credentials, no payment, no
  gift cards, no bank details, no link to a login page.

## Step 6 — Verdict

**LEGITIMATE / LOW RISK — clear it.**

Evidence: full authentication pass with DMARC alignment to the real, consistent
brand domain; a mainstream ESP relay; no malicious payload; and only a resume/rate
request. The "scary-looking" elements (relay, pixels, urgency) are normal marketing
mechanics, not attack indicators.

**One analyst caveat:** unsolicited staffing email is a known *lure category* — real
recruiters and scammers both cold-email job seekers. So while *this message* is
benign, the correct posture is: engage only through the verified `viva-it.com`
channel, and treat any later step that asks for bank details, a "deposit check," or
software installs as a fresh trigger to re-triage. Authentication clears the sender;
it doesn't switch off judgment on future requests.

## Indicators recorded

- Sender: `afsarr@viva-it.com`  | Return-path: `em3310.viva-it.com`
- Sending IP: `149.72.40.63` (SendGrid) | Auth: SPF/DKIM/DMARC all pass, aligned
- Disposition: **allow / no action** — legitimate business sender

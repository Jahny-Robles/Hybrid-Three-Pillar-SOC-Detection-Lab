# Writeup 02 — "Cloud Storage" payment phish → verdict: MALICIOUS

**Source:** A **real phishing email I pulled from my own Gmail spam folder** (23 Jul
2026) and analyzed from the raw headers. My own address is redacted; all URLs are
defanged. This is a live specimen, not a constructed sample — the analysis below is
my own read of the evidence.

## The email

- **From (display):** `𝗣aym𝗲nt_Declin𝗲d` — written with Unicode bold look-alike
  characters (𝗣, 𝗲) instead of normal letters, to slip the string past keyword filters
- **From (address):** `djzyiuzlfpb@iuat.oydhtestpxkqd.us` — random string on a
  nonsense domain
- **Subject:** `roblesjahny Account Has been Blocked! Your Photos and Videos will be
  Removed Thu,23 Jul-2026 . take action!`
- **Body:** "Payment Issue – Cloud Storage" — claims a subscription renewal failed,
  shows a fake "96% Storage Used" bar, a 4-minute countdown, and an **Update Payment
  Details** button.

## Step 1 — Authentication results

From Gmail's "Show original" summary:

- **SPF: PASS** (IP `23.106.58.119`, for sending domain `5557148[.]com`)
- **DKIM: none** (no valid signature)
- **DMARC: FAIL**

**Reading it:** SPF passing means only that the server was authorized to send for the
throwaway domain `5557148[.]com` — it says nothing about legitimacy. **DMARC fails**
because the domain the user sees in `From:` (`oydhtestpxkqd[.]us`) is not
authenticated or aligned to any real sender. So the one "pass" here is meaningless
for trust, and the check that actually ties authentication to the visible sender —
DMARC — fails outright. (Contrast with [writeup 01](01-benign-recruiter.md), which
was SPF/DKIM/DMARC **all pass and aligned** to the real brand domain.)

## Step 2 — Sender identity (my first red flag)

The email presents itself as "Cloud Storage," but the sending address
(`...@iuat.oydhtestpxkqd[.]us`) has **no association with any real cloud provider** —
it's not microsoft.com, aws, Google, Oracle Cloud, or anything recognizable. A real
provider sends from its own brand domain. Random-string sender + nonsense domain +
generic "Cloud Storage" branding = impersonation.

## Step 3 — The threat is logically impossible (my strongest tell)

The subject claims my **photos and videos will be deleted the same day** a payment is
declined. **No legitimate cloud provider does this.** Real providers give grace
periods, send multiple notices, and downgrade or lock an account long before deleting
anyone's data. A "your files are gone today unless you act now" threat exists only to
manufacture panic — the impossible timeline is itself the evidence of a scam, not
just generic urgency.

## Step 4 — Manufactured false trust (my third tell)

The email includes a **"Security Recommendations"** block — "always access your
account through our official website," "never share your password." This mimics the
reassuring language real companies use, specifically to lower an inexperienced user's
guard *while the actual button harvests their payment details*. Dressing a phish in
safety advice is a manipulation tactic, not a sign of legitimacy.

## Step 5 — The link is the real payload (trusted-service abuse)

The **Update Payment Details** button (and the whole body) links to:

`hxxps://storage.googleapis[.]com/gocommercially/filipinomarketers.html#<hex-encoded-data>`

This is the clever part: the attacker hosts the phishing page inside
**`storage.googleapis.com` — Google's own legitimate cloud-storage service** — so the
URL looks trustworthy at a glance and can slip past domain-reputation filters. The
real malicious object is the uploaded file `filipinomarketers.html`; the long hex
string after `#` is encoded data (likely my address, to pre-fill the fake page).
Living-off-trusted-services: hide the payload on a domain everyone trusts.

## Step 6 — Supporting flags

- **Fake bounce wrapper:** the message is built as a `multipart/report;
  report-type=delivery-status` — disguised as an automated delivery failure so it
  reads as system-generated. Gmail flagged it as an auto-reply "that pretended to be
  sent from your email address."
- **Generic greeting:** "Dear User" — a real provider knows my name.
- **Hidden filler text:** the raw source is padded with unrelated scraped content
  (rental confirmations, news articles, app signups) in hidden blocks — a trick to
  dilute spam-keyword ratios and fool content filters. Legitimate mail never does this.

## Step 7 — Verdict

**MALICIOUS — phishing (payment/credential harvest), T1566.002 (phishing link).**

Impersonates a cloud provider from an unrelated nonsense domain; fails DMARC; uses an
impossible same-day data-deletion threat plus a countdown to force panic; disguises
itself with fake security advice; and routes to a payload hidden on Google's own
storage domain. The single SPF pass is on a throwaway sender and doesn't change any
of this.

## Step 8 — Tier 1 actions

- **Do not click** the button or visit the link.
- **Report** as phishing (Gmail "Report phishing"); it's already correctly in spam.
- In a corporate SOC: **record IOCs** (sender domain, sending IP, the
  `storage.googleapis.com` payload URL) and **hunt** for the same campaign hitting
  other users; pull/quarantine copies.
- If any user clicked or entered payment/credentials → treat as a **fraud /
  credential-exposure incident**: notify the user, guide a card reissue / password
  reset, and escalate.

## Indicators recorded (defanged)

- Sender: `djzyiuzlfpb@iuat.oydhtestpxkqd[.]us` | envelope domain `5557148[.]com`
- Sending IP: `23.106.58.119`
- Payload URL: `hxxps://storage.googleapis[.]com/gocommercially/filipinomarketers.html`
- Auth: SPF pass (throwaway domain) · DKIM none · **DMARC fail**
- Technique: **T1566.002** (Phishing: Spearphishing Link); payment/credential harvest
- Disposition: **do-not-click + report + hunt + escalate on interaction**

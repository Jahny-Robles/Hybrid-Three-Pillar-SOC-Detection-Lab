# Email Triage Methodology

This is the process I follow to triage any suspicious email. It's designed to be
repeatable and evidence-based — the verdict comes from what the headers and content
actually show, not from a gut feeling that an email "looks scary."

## Step 0 — Handle safely

- Work from the **raw source / headers**, not the rendered email.
  (In Gmail: open the message → three-dot menu → **Show original**.)
- Never click links or open attachments to "check." Inspect them as text.
- Defang anything I record: `hxxps://`, `bad-domain[.]com`.

## Step 1 — Read the authentication results

The single most objective signal. In the `Authentication-Results` header, I check:

- **SPF** — did the sending IP have permission to send for the envelope domain?
- **DKIM** — is the message cryptographically signed, and does the signature verify?
- **DMARC** — does the visible `From:` domain align with the authenticated domain,
  and what policy does that domain publish (none / quarantine / reject)?

See [spf-dkim-dmarc.md](spf-dkim-dmarc.md) for what each one actually proves.

Key idea: **SPF/DKIM/DMARC pass tells me the mail genuinely came from the domain it
claims — it does NOT tell me the domain is trustworthy.** A phisher who owns
`paypa1-support[.]com` can pass all three from their own domain. Authentication is
about *authenticity of origin*, not *intent*.

## Step 2 — Check domain alignment and identity

- Does the `From:` **display name** match the actual **email address**?
  (Display "PayPal Support" from `billing@random-domain[.]info` is a red flag.)
- Is the `From:` domain the **real** brand domain, or a **lookalike**?
  (`micros0ft`, `paypal-secure`, `amazon[.]account-verify[.]com`.)
- Does the authenticated domain (DKIM `d=`) match the brand it's impersonating?

## Step 3 — Trace the Received chain

- Read `Received:` headers **bottom-up** (oldest = origin).
- Identify the true originating IP and mail infrastructure.
- Note legitimate ESPs (SendGrid, Mailchimp, Amazon SES) — these are normal for
  bulk/marketing mail and are **not** by themselves suspicious.

## Step 4 — Inspect links and attachments (as text)

- Hover-equivalent: read the real `href`, not the anchor text. Anchor says
  `www.bank.com`, href points to `hxxp://bank-verify[.]ru` → mismatch = red flag.
- Watch for URL shorteners, IP-address URLs, and credential-form landing pages.
- Attachments: flag unexpected `.htm/.html`, `.iso`, `.zip`, macro-enabled Office
  (`.docm/.xlsm`), `.lnk`, or double extensions (`invoice.pdf.exe`).

## Step 5 — Read the content for social-engineering pressure

- Urgency / threat ("account will be suspended in 24h").
- Unusual requests (buy gift cards, change payroll/bank details, wire funds).
- Authority + secrecy ("I'm in a meeting, keep this between us").
- Generic greeting + specific payload, or reply-to that differs from From.

## Step 6 — Weigh and decide

I don't count red flags mechanically; I weigh them. Authentication and domain
alignment are heavy signals. A tracking pixel or mild urgency in an otherwise
authenticated, aligned email is low-weight. The verdict is one of:

- **Malicious** — block sender/domain, pull related messages, report, escalate if
  it hit multiple users or a payload was delivered.
- **Suspicious / needs verification** — auth is clean but the *request* is risky;
  verify the sender through a known channel before any action.
- **Benign** — authenticated, aligned, no risky payload or request. Clear it.

## Step 7 — Record indicators (IOCs)

Sender address, envelope/return-path, originating IP, sending domain, any defanged
URLs/domains, attachment hashes if present, and the MITRE ATT&CK technique
(usually T1566). These are what get shared and blocked.

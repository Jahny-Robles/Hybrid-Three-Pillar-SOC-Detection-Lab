# Runbook — Suspicious Email Triage (Tier 1)

A one-page playbook for triaging a reported/suspicious email. Designed for a Tier 1
analyst to follow start to finish and reach a defensible disposition.

## Trigger
User-reported email, phishing-mailbox submission, or SEG/SIEM alert on inbound mail.

## Do first (safety)
1. Work from **raw headers/source**, not the rendered message.
2. **Do not** click links or open attachments. Inspect as text.
3. Defang everything you record: `hxxps://`, `domain[.]com`.

## Triage steps
1. **Auth check** — read `Authentication-Results`: SPF / DKIM / DMARC pass or fail?
   - Remember: pass = *authentic origin*, not *trustworthy*.
2. **Identity/alignment** — does From display match the address? Is the domain the
   **real** brand or a **lookalike**? Is DMARC aligned to the *brand* or to a
   throwaway/lookalike domain?
3. **Received chain** — trace origin IP/infrastructure (bottom-up). Note if it's a
   normal ESP (SendGrid, SES) vs. suspicious origin.
4. **Links/attachments** — read real `href`s; flag lookalike/shortener/IP URLs and
   high-risk attachments (`.htm`, `.iso`, `.xlsm/.docm`, `.lnk`, double extensions).
5. **Content** — urgency, authority, secrecy, unusual money/credential/data requests,
   mismatched Reply-To.

## Decision
| Verdict | When | Action |
|---------|------|--------|
| **Benign** | Authenticated + aligned to real sender, no risky payload/request | Allow / no action; close |
| **Suspicious** | Auth clean but request is risky (e.g. unsolicited, asks for money/creds later) | Verify sender out-of-band before any action |
| **Malicious** | Spoof/lookalike, failed auth + risky payload, or BEC social-engineering | Block, hunt, report, escalate |

## If malicious
1. **Block** sender address/domain, landing domain, and file hash.
2. **Hunt** the mail environment for other recipients; pull/quarantine copies.
3. **Assess impact** — did anyone click, enter credentials, open the attachment,
   or act on the request?
   - Credentials entered → force reset + revoke sessions + check mailbox rules.
   - Attachment opened → isolate host, investigate for compromise.
   - Payment/gift-card sent → notify finance + escalate immediately.
4. **Report** to the phishing mailbox / ticket; record IOCs.
5. **Escalate** to Tier 2/3 if multiple users, confirmed compromise, or payload
   execution.

## Record (IOCs)
Sender + return-path, origin IP, sending domain, defanged URLs/domains, attachment
name + hash, MITRE technique (**T1566** family), disposition, and affected users.

## MITRE mapping
- **T1566.001** Phishing: Spearphishing Attachment
- **T1566.002** Phishing: Spearphishing Link
- **T1566** / social engineering (BEC, financial fraud — often no link/attachment)
